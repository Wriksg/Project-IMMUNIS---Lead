from __future__ import annotations
from immunis.contracts.models import TaintTag, Trust, Origin

def stamp(source_id: str, trust: Trust, origin: Origin) -> TaintTag:
    return TaintTag(source_id=source_id, trust=trust, origin=origin)

def derive(parents: list[TaintTag], origin: Origin, source_id: str) -> TaintTag:
    trust = Trust.untrusted if any(p.trust == Trust.untrusted for p in parents) else Trust.trusted
    return TaintTag(source_id=source_id, trust=trust, origin=origin,
                    parents=[p.source_id for p in parents])

def merge(tags: list[TaintTag]) -> TaintTag:
    if not tags:
        return stamp("empty", Trust.trusted, Origin.user)
    trust = Trust.untrusted if any(t.trust == Trust.untrusted for t in tags) else Trust.trusted
    return TaintTag(source_id="merged:" + ",".join(sorted(t.source_id for t in tags)),
                    trust=trust, origin=Origin.memory_recall,
                    parents=sorted({p for t in tags for p in t.parents} | {t.source_id for t in tags}))
