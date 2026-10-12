from __future__ import annotations
import json
from pathlib import Path
from typing import Any

_ROLES = ("soma", "thymus_fast", "thymus_deep", "plasma", "antigen_bulk")


def _model_from_config(role: str = "soma") -> str:
    cfg = Path(__file__).resolve().parents[2] / "config" / "models.yaml"
    if not cfg.exists():
        raise RuntimeError(f"missing config/models.yaml for role {role}")
    found: str | None = None
    current: str | None = None
    for line in cfg.read_text().splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key in _ROLES and val:
            current = val
        if key == role and val:
            found = val
    if found:
        return found
    if current:
        return current
    raise RuntimeError(f"no model configured for role {role}")


class LLMClient:
    """Client for a reasoning model: reads only message.content and
    message.tool_calls; tolerates content=None."""

    def __init__(self, role: str = "soma", max_tokens: int = 2000) -> None:
        self.model = _model_from_config(role)
        self.max_tokens = max(1500, max_tokens)

    def chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        # Wire actual API client here; response parsing below is the contract.
        response = self._raw_chat(messages)
        message = (response.get("choices") or [{}])[0].get("message") or {}
        content = message.get("content")  # may be None for tool-only turns
        tool_calls = [
            {"name": tc["function"]["name"],
             "arguments": json.loads(tc["function"]["arguments"] or "{}")}
            for tc in (message.get("tool_calls") or [])
        ]
        return {"content": content, "tool_calls": tool_calls}

    def _raw_chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError("wire provider client here")


class ScriptedLLM:
    """Deterministic test double: yields scripted turns."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.i = 0
        self.sent: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        self.sent.append(list(messages))
        turn = self.script[self.i] if self.i < len(self.script) else "done"
        self.i += 1
        if isinstance(turn, str):
            return {"content": turn, "tool_calls": []}
        return {"content": None,
                "tool_calls": [{"name": n, "arguments": a} for n, a in turn]}
