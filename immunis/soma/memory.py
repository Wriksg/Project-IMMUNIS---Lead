from __future__ import annotations
import json
from pathlib import Path
from immunis.contracts.models import TaintTag

DEFAULT_MEMORY_PATH = "runs/memory.json"

class MemoryStore:
    def __init__(self, path: str = DEFAULT_MEMORY_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: dict[str, dict] = {}
        if self.path.exists():
            self.entries = json.loads(self.path.read_text() or "{}")

    def snapshot(self) -> dict:
        return json.loads(json.dumps(self.entries))

    def diff(self, before: dict) -> dict:
        return {"added": [k for k in self.entries if k not in before]}

    def write(self, content: str, taint: TaintTag, quarantined: bool = False) -> dict:
        entry_id = f"mem_{len(self.entries) + 1:04d}"
        self.entries[entry_id] = {"content": content, "taint": taint.model_dump(),
                                  "quarantined": quarantined}
        self.path.write_text(json.dumps(self.entries, indent=2))
        return {"id": entry_id, **self.entries[entry_id]}

    def search(self, query: str) -> dict:
        hits = [{"id": k, "content": v["content"], "taint": v["taint"]}
                for k, v in self.entries.items() if query.lower() in v["content"].lower()]
        return {"output": json.dumps(hits), "hits": hits}
