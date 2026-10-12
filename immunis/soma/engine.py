"""SOMA agent loop. Stub LLM (intent routing) — zero defences, emits full Episode."""

import time
import uuid

from immunis.contracts.models import Episode, ToolCall, TaintTag, Origin, Trust
from immunis.soma.taint import stamp, derive
from immunis.soma import tools
from immunis.soma.policy import quarantine_required
from immunis.soma.memory import MemoryStore, DEFAULT_MEMORY_PATH


class SOMA:
    def __init__(self, policy_version: int = 0, memory_path: str = DEFAULT_MEMORY_PATH):
        self.policy_version = policy_version  # zero antibodies at start
        self.memory = MemoryStore(memory_path)
        self.transcript: list[dict] = []
        self.tool_calls: list[ToolCall] = []

    def run(self, user_input: str, attack_id: str | None = None,
            benign_task_id: str | None = None) -> Episode:
        # Episode schema demands exactly one trigger id; default to a smoke benign task
        if attack_id is None and benign_task_id is None:
            benign_task_id = "ben_smoke"
        start = time.perf_counter()
        self.transcript, self.tool_calls = [], []
        before = self.memory.snapshot()

        input_taint = stamp("user_input", Trust.trusted, Origin.user)
        self._log("user", user_input, input_taint)

        lowered = user_input.lower()

        if ("summariz" in lowered or "summaris" in lowered) and (
            "inbox" in lowered or "webpage" in lowered or "email" in lowered
        ):
            if "inbox" in lowered or "email" in lowered:
                self._do_read_inbox("msg_001")
            else:
                self._do_fetch("webpage:quarterly_report")
            summary, taint = self._summarize_last()
            self._do_write_memory(summary, taint)
            if "send" in lowered:
                self._do_send("alice@corp.com", summary, taint)
        elif "read inbox" in lowered:
            self._do_read_inbox("msg_001")
        else:
            self._log(
                "soma",
                "I can summarize a page, read your inbox, or search memory.",
                input_taint,
            )

        wall = int((time.perf_counter() - start) * 1000)
        return Episode(
            id=f"ep_{uuid.uuid4().hex[:8]}",
            attack_id=attack_id,
            benign_task_id=benign_task_id,
            policy_version=self.policy_version,
            transcript=self.transcript,
            tool_calls=self.tool_calls,
            memory_diff=self.memory.diff(before),
            wall_clock_ms=wall,
            token_count=0,
            fixture_set_id="fixtures_v1",
        )

    # ---------- tool wrappers ----------
    def _do_fetch(self, url: str):
        r = tools.fetch_webpage(url)
        self._record(r, permitted=True)
        self._log("tool", r.output, r.taint)
        self._last_page_taint, self._last_page_text = r.taint, r.output

    def _do_read_inbox(self, message_id: str):
        r = tools.read_inbox(message_id)
        self._record(r, permitted=True)
        self._log("tool", r.output, r.taint)
        self._last_page_taint, self._last_page_text = r.taint, r.output

    def _summarize_last(self):
        # CRITICAL: taint never launders — untrusted stays untrusted
        summary = self._last_page_text[:120]
        return summary, derive(self._last_page_taint, Origin.soma_summary, "summary")

    def _do_write_memory(self, content: str, taint: TaintTag):
        entry = self.memory.write(content, taint, quarantined=quarantine_required(taint))
        self.tool_calls.append(ToolCall(
            name="write_memory",
            arguments={"content": content},
            taint_trace={"taint": taint},
            permitted=True,
            blocking_antibody_id=None,
        ))
        self._log("memory", f"wrote {entry.id} quarantined={entry.quarantined}", taint)

    def _do_send(self, to: str, body: str, taint: TaintTag):
        # ZERO DEFENCES: permitted even when taint is untrusted. Thymus must catch this.
        r = tools.send_message(to, body, taint)
        self._record(r, permitted=True)

    # ---------- helpers ----------
    def _record(self, result, permitted: bool):
        self.tool_calls.append(ToolCall(
            name=result.name,
            arguments=result.args,
            taint_trace={"taint": result.taint},
            permitted=permitted,
            blocking_antibody_id=None,
        ))

    def _log(self, role: str, content: str, taint: TaintTag):
        self.transcript.append({
            "role": role,
            "content": content,
            "taint": taint.model_dump(),
        })
