"""Persistent memory. Stores and reloads contract MemoryEntry models."""
import json
from pathlib import Path

from immunis.contracts.models import MemoryEntry, TaintTag


class MemoryStore:
    def __init__(self, path: str = "memory.json"):
        self.path = Path(path)
        self.entries: dict[str, MemoryEntry] = {}
        if self.path.exists():
            raw = json.loads(self.path.read_text() or "{}")
            self.entries = {
                k: MemoryEntry.model_validate(v) for k, v in raw.items()
            }

    def write(self, content: str, taint: TaintTag,
              quarantined: bool = False) -> MemoryEntry:
        entry_id = f"mem_{len(self.entries) + 1:04d}"
        entry = MemoryEntry(id=entry_id, text=content,
                            tag=taint, quarantined=quarantined)
        self.entries[entry_id] = entry
        self._persist()
        return entry

    def read(self, entry_id: str) -> MemoryEntry:
        return self.entries[entry_id]

    def all_entries(self) -> list[MemoryEntry]:
        return list(self.entries.values())

    def _persist(self) -> None:
        self.path.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.entries.items()}, indent=2))
