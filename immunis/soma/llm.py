from __future__ import annotations
import os
import time
from pathlib import Path
from typing import Any

_BASE_URL = "https://integrate.api.nvidia.com/v1"
_FALLBACK_MODEL = "meta/llama-3.1-70b-instruct"

def _load_dotenv() -> None:
    env_file = Path(__file__).resolve().parents[2] / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_dotenv()

def _model_from_config() -> str:
    cfg = Path(__file__).resolve().parents[2] / "config" / "models.yaml"
    if cfg.exists():
        for line in cfg.read_text().splitlines():
            if line.strip().startswith("soma:"):
                return line.split(":", 1)[1].strip().strip('"')
    return _FALLBACK_MODEL

class LLMClient:
    def __init__(self) -> None:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            raise RuntimeError("NVIDIA_API_KEY not set. Put it in .env at repo root.")
        from openai import OpenAI
        self._client = OpenAI(base_url=_BASE_URL, api_key=api_key)
        self.model = _model_from_config()

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        kwargs: dict[str, Any] = dict(model=self.model, messages=messages, temperature=0)
        if tools:
            kwargs["tools"] = [{"type": "function", "function": t} for t in tools]
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                resp = self._client.chat.completions.create(**kwargs)
                msg = resp.choices[0].message
                return {"content": msg.content,
                        "tool_calls": [{"name": tc.function.name,
                                        "arguments": tc.function.arguments}
                                       for tc in (msg.tool_calls or [])],
                        "usage": {"total_tokens": resp.usage.total_tokens}}
            except Exception as e:
                last_err = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM call failed after 3 attempts: {last_err}")

class ScriptedLLM:
    def __init__(self, script: list):
        self.script = list(script)

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        if not self.script:
            return {"content": "done", "tool_calls": [], "usage": {"total_tokens": 0}}
        step = self.script.pop(0)
        if isinstance(step, str):
            return {"content": step, "tool_calls": [], "usage": {"total_tokens": 10}}
        return {"content": None,
                "tool_calls": [{"name": n, "arguments": a} for n, a in step],
                "usage": {"total_tokens": 10}}
