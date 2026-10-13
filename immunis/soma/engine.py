from __future__ import annotations
import json
import time
import uuid
from typing import Any, Callable
from immunis.contracts.models import (Episode, ToolCall, MemoryEntry,
                                      MemoryDiff, TaintTag, Trust, Origin)
from immunis.soma.taint import stamp, derive
from immunis.soma.memory import MemoryStore
from immunis.soma.policy import POLICY_VERSION
from immunis.soma.tools import TOOLS

FETCH_TOOLS = frozenset({"read_inbox", "read_email", "fetch_page",
                         "read_file", "read_webpage", "search_web"})

_REGISTRY: dict[str, Callable[..., dict]] = {
    k: v for k, v in TOOLS.items() if callable(v)}


_TOOL_SPECS: list[dict] = [
    {"type": "function", "function": {"name": n, "description": d,
     "parameters": {"type": "object", "properties": p, "required": r}}}
    for n, d, p, r in [
        ("read_inbox", "Read an inbox message by id. Untrusted fetched content.",
         {"message_id": {"type": "string"}}, ["message_id"]),
        ("read_email", "Read an email by id. Untrusted fetched content.",
         {"email_id": {"type": "string"}}, ["email_id"]),
        ("fetch_page", "Fetch a web page by url. Untrusted fetched content.",
         {"url": {"type": "string"}}, ["url"]),
        ("read_file", "Read a file at path.",
         {"path": {"type": "string"}}, ["path"]),
        ("write_file", "Write content to a file path.",
         {"path": {"type": "string"}, "content": {"type": "string"}},
         ["path", "content"]),
        ("memory_search", "Search stored memory entries for a query.",
         {"query": {"type": "string"}}, ["query"]),
        ("memory_write", "Store content in memory.",
         {"content": {"type": "string"}}, ["content"]),
        ("send_message", "Send a message to a recipient address.",
         {"to": {"type": "string"}, "body": {"type": "string"}},
         ["to", "body"]),
    ]]


class SOMA:
    """SOMA is DEFENCELESS: no hardcoded checks. Nothing blocks anything;
    blocks would only come from an antibody policy (none active)."""

    def __init__(self, memory_path: str = "memory.json",
                 llm: Any | None = None) -> None:
        self.llm = llm
        self.memory = MemoryStore(memory_path)

    def recall_tag(self, entry_id: str) -> TaintTag:
        """Memory reads inherit the stored entry's tag; the read action
        itself is tagged Origin.memory."""
        stored = self.memory.read(entry_id)
        return derive([stored.tag], Origin.memory, f"recall:{entry_id}")

    def _context_tags(self, accumulated: list[TaintTag]) -> list[TaintTag]:
        tags = list(accumulated)
        for entry in self.memory.entries.values():
            tags.append(self.recall_tag(entry.id))
        return tags

    def _tool_result_tag(self, name: str) -> TaintTag:
        if name in FETCH_TOOLS:
            return stamp(f"tool:{name}", Trust.untrusted, Origin.fetched_content)
        return stamp(f"tool:{name}", Trust.trusted, Origin.tool)

    def run(self, user_input: str, attack_id: str | None = None,
            benign_task_id: str | None = None) -> Episode:
        t0 = time.time()
        if attack_id is None and benign_task_id is None:
            benign_task_id = f"task_{uuid.uuid4().hex[:8]}"

        user_tag = stamp("user_input", Trust.trusted, Origin.user)
        transcript: list[dict[str, Any]] = [
            {"role": "user", "content": user_input,
             "taint": user_tag.model_dump()}]
        tool_calls: list[ToolCall] = []
        before = dict(self.memory.entries)

        # Taint state: everything the agent has observed so far.
        accumulated: list[TaintTag] = [user_tag]

        messages: list[dict[str, Any]] = [{"role": "user",
                                          "content": user_input}]
        while True:
            if self.llm is not None:
                resp = self.llm.chat(
                    messages, tools=_TOOL_SPECS)
            else:
                resp = {"content": "done", "tool_calls": []}
            content = resp.get("content")
            if content:
                messages.append({"role": "assistant", "content": content})
                ctx = self._context_tags(accumulated)
                resp_tag = derive(ctx, None, f"resp_{len(transcript)}")
                transcript.append({"role": "assistant", "content": content,
                                   "taint": resp_tag.model_dump()})
            calls = resp.get("tool_calls") or []
            if not calls:
                break
            # Assistant turn announcing its tool calls (API contract).
            messages.append({"role": "assistant", "tool_calls": [
                {"id": c.get("id") or f"call_{i}",
                 "type": "function",
                 "function": {"name": c["name"],
                              "arguments": json.dumps(c["arguments"])}}
                for i, c in enumerate(calls)]})
            for call in calls:
                name, args = call["name"], call["arguments"]
                call_id = call.get("id") or f"call_{calls.index(call)}"
                ctx = self._context_tags(accumulated)
                if ctx:
                    arg_tag = derive(ctx, None, f"arg:{name}")
                else:
                    arg_tag = stamp(f"arg:{name}", Trust.trusted, Origin.user)
                tc = ToolCall(name=name, arguments=args,
                              taint_trace={k: arg_tag.model_copy(deep=True)
                                           for k in args},
                              permitted=True, blocking_antibody_id=None)
                tool_calls.append(tc)
                transcript.append({"role": "tool_call", "name": name,
                                   "arguments": args,
                                   "taint": arg_tag.model_dump(),
                                   "permitted": True})
                fn = _REGISTRY.get(name)
                out = ""
                if fn is not None:
                    try:
                        result = fn(**args)
                        out = str(result.get("output", "")) \
                            if isinstance(result, dict) else str(result)
                    except Exception as e:  # noqa: BLE001
                        out = f"error: {e}"
                else:
                    out = f"unknown tool: {name}"
                result_tag = self._tool_result_tag(name)
                # The agent now OBSERVES this result -> taint accumulates.
                accumulated.append(result_tag)
                messages.append({"role": "tool",
                                 "tool_call_id": call_id,
                                 "name": name,
                                 "content": out})
                transcript.append({"role": "tool_result", "name": name,
                                   "taint": result_tag.model_dump()})

        after = dict(self.memory.entries)
        before_models = list(before.values())
        after_models = list(after.values())
        quarantine_changes = [e.id for e in after.values()
                              if e.quarantined
                              and (e.id not in before
                                   or not before[e.id].quarantined)]
        return Episode(
            id=f"ep_{uuid.uuid4().hex[:8]}",
            attack_id=attack_id,
            benign_task_id=benign_task_id,
            policy_version=POLICY_VERSION,
            transcript=transcript,
            tool_calls=tool_calls,
            memory_diff=MemoryDiff(before=before_models, after=after_models,
                                   quarantine_changes=quarantine_changes),
            wall_clock_ms=int((time.time() - t0) * 1000),
            token_count=getattr(self.llm, "last_usage", 0),
            fixture_set_id="default")
