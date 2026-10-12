"""Taint stamping and propagation primitives.

Invariants:
  - Trust is sticky: derived/merged taint takes the WORST (highest
    _TRUST_ORDER value) of its inputs. Trust is never raised.
  - Provenance is append-only: parents only grow.
  - Origin describes where the content came from; derive() replaces it.
"""

from immunis.contracts.models import TaintTag, Trust, Origin

_TRUST_ORDER = {
    Trust.trusted: 0,
    Trust.semi_trusted: 1,
    Trust.untrusted: 2,
}


def stamp(
    source_id: str,
    trust: Trust = Trust.untrusted,
    origin: Origin = Origin.fetched_content,
) -> TaintTag:
    """Create a fresh root taint tag."""
    return TaintTag(origin=origin, trust=trust, source_id=source_id, parents=[])


def derive(
    parents: list[TaintTag] | TaintTag,
    new_origin: Origin,
    label: str = "",
) -> TaintTag:
    """Content derived from tainted content inherits the WORST taint.

    - trust: minimum trust of all parents (sticky, never raised)
    - parents: union of all parents' parent sets + their source_ids (grows)
    - origin: replaced by new_origin
    - source_id: label
    """
    if isinstance(parents, TaintTag):
        parents = [parents]
    if not parents:
        raise ValueError("derive() requires at least one parent TaintTag")

    # Highest rank value == least trusted
    trust = max(parents, key=lambda t: _TRUST_ORDER[t.trust]).trust
    parent_ids = sorted(
        {p for t in parents for p in t.parents} | {t.source_id for t in parents}
    )

    return TaintTag(
        origin=new_origin,
        trust=trust,
        source_id=label,
        parents=parent_ids,
    )


def merge(tags: list[TaintTag]) -> TaintTag:
    """Lowest trust wins; parent histories are unioned."""
    if not tags:
        raise ValueError("Cannot merge empty list of TaintTags")

    worst = max(tags, key=lambda t: _TRUST_ORDER[t.trust])
    all_parents = list(
        {p for t in tags for p in t.parents} | {t.source_id for t in tags}
    )

    return TaintTag(
        origin=worst.origin,
        trust=worst.trust,
        source_id="merged",
        parents=all_parents,
    )
