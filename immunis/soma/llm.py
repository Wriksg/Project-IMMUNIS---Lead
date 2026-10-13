from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Any

from openai import OpenAI, InternalServerError, RateLimitError

_ROLES = ("soma", "thymus_fast", "thymus_deep", "plasma", "antigen_bulk")


def _model_from_config(role: str = "soma") -> str:
    cfg = Path(__file__).resolve().parents[2] / "config" / "models.yaml"
    if not cfg.exists():
        raise RuntimeError(f"missing config/models.yaml for role {role}")
    found: str | None = None
    for line in cfg.read_text().splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key == role and val:
            found = val
    if not found:
        raise RuntimeError(f"no model configured for role {role}")
    return found


class LLMClient:
    """Client for a reasoning model: reads only message.content and
    message.tool_calls; tolerates content=None."""

    def __init__(self, role: str = "soma", max_tokens: int = 2000) -> None:
        self.model = _model_from_config(role)
        self.max_tokens = max(1500, max_tokens)
        self.last_usage = 0
        self.last_wall_ms = 0
        from dotenv import load_dotenv
        load_dotenv(override=False)
        key = os.environ.get("NVIDIA_API_KEY")
        if not key:
            raise RuntimeError("NVIDIA_API_KEY not set (env or .env)")
        self._client = OpenAI(
            api_key=key,
            base_url="https://integrate.api.nvidia.com/v1")

    def chat(self, messages: list[dict[str, Any]],
             tools: list[dict] | None = None) -> dict[str, Any]:
        t0 = time.perf_counter()
        response = self._raw_chat(messages, tools)
        self.last_wall_ms = int((time.perf_counter() - t0) * 1000)
        usage = response.get("usage")
        self.last_usage = usage.get("total_tokens", 0) if usage else 0
        message = (response.get("choices") or [{}])[0].get("message") or {}
        content = message.get("content")
        tool_calls = []
        for tc in (message.get("tool_calls") or []):
            raw = tc["function"]["arguments"] or "{}"
            try:
                args = json.loads(raw)
            except json.JSONDecodeError as exc:
                # Malformed JSON: recorded in transcript, treated as failed
                args = {"_error": f"malformed arguments: {exc}", "_raw": raw}
            tool_calls.append({"id": tc.get("id"),
                               "name": tc["function"]["name"],
                               "arguments": args})
        return {"content": content if content is not None else "",
                "tool_calls": tool_calls}

    def _raw_chat(self, messages: list[dict[str, Any]],
                  tools: list[dict] | None = None) -> dict[str, Any]:
        kwargs: dict = dict(model=self.model, messages=messages,
                            max_tokens=self.max_tokens)
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        delay = 2.0
        for attempt in range(4):
            try:
                return self._client.chat.completions.create(**kwargs).model_dump()
            except (InternalServerError, RateLimitError):
                if attempt == 3:
                    raise
                time.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")


class ScriptedLLM:
    """Deterministic test double: yields scripted turns."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.i = 0
        self.sent: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]],
             tools: list[dict] | None = None) -> dict[str, Any]:
        self.sent.append(list(messages))
        turn = self.script[self.i] if self.i < len(self.script) else "done"
        self.i += 1
        if isinstance(turn, str):
            return {"content": turn, "tool_calls": []}
        return {"content": None,
                "tool_calls": [{"id": f"c{i}", "name": n, "arguments": a}
                               for i, (n, a) in enumerate(turn)]}
