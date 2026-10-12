"""Quarantined memory store for SOMA. Write-through to disk on every write."""
import json, os, uuid
from immunis.contracts.models import MemoryEntry, MemoryDiff, TaintTag

DEFAULT_MEMORY_PATH = "memory.json"   # single default, one place


class MemoryStore:
    def __init__(self, path: str = DEFAULT_MEMORY_PATH):
        self.path = path
        self.entries: dict[str, MemoryEntry] = {}
        if os.path.exists(path):
            with open(path) as f:
                for raw in json.load(f):
                    e = MemoryEntry(**raw)
                    self.entries[e.id] = e

    def write(self, text: str, tag: TaintTag, quarantined: bool = False) -> MemoryEntry:
        # NOTE: quarantine is a POLICY decision, not a taint default (see B).
        entry = MemoryEntry(id=f"mem_{uuid.uuid4().hex[:8]}", text=text,
                            tag=tag, quarantined=quarantined)
        self.entries[entry.id] = entry
        self._flush()
        return entry

    def snapshot(self) -> list[MemoryEntry]:
        return list(self.entries.values())

    def diff(self, before: list[MemoryEntry]) -> MemoryDiff:
        after = self.snapshot()
        before_q = {e.id for e in before if e.quarantined}
        return MemoryDiff(before=before, after=after,
                          quarantine_changes=[e.id for e in after
                                              if e.quarantined and e.id not in before_q])

    def _flush(self):
        with open(self.path, "w") as f:
            json.dump([e.model_dump() for e in self.entries.values()], f, indent=2)