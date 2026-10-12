from __future__ import annotations
from immunis.contracts.models import TaintTag, Trust, Origin


def stamp(source_id: str, trust: Trust, origin: Origin) -> TaintTag:
    return TaintTag(source_id=source_id, trust=trust, origin=origin,
                    parents=[])


def derive(parents: list[TaintTag],
           origin: Origin | None,
           source_id: str) -> TaintTag:
    trust = (Trust.untrusted if any(p.trust == Trust.untrusted for p in parents)
             else Trust.trusted)
    if origin is None:
        # Inherit origin from the tainting parent(s); fall back to trusted
        # parents' origin, then user.
        bad = [p for p in parents if p.trust == Trust.untrusted]
        pool = bad if bad else parents
        origin = pool[0].origin if pool else Origin.user
    return TaintTag(source_id=source_id, trust=trust, origin=origin,
                    parents=[p.source_id for p in parents])


def merge(tags: list[TaintTag]) -> TaintTag:
    if not tags:
        return stamp("empty", Trust.trusted, Origin.user)
    return TaintTag.merge(tags)
