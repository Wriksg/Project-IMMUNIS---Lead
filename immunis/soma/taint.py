"""Taint stamping at SOMA's entry boundaries."""
from immunis.contracts.models import TaintTag, Trust, Origin


def stamp(origin: Origin, source_id: str, trust: Trust | None = None,
          parents: list[str] | None = None) -> TaintTag:
    """Stamp text at the boundary. Content inside fetched/email/doc surfaces is always untrusted."""
    if trust is None:
        trust = {
            Origin.user: Trust.trusted,
            Origin.system: Trust.trusted,
            Origin.tool: Trust.semi_trusted,
            Origin.fetched_content: Trust.untrusted,
            Origin.memory: Trust.untrusted,      # caller overrides with stored tag
            Origin.soma_summary: Trust.untrusted,
        }[origin]
    return TaintTag(origin=origin, trust=trust, source_id=source_id, parents=parents or [])


def derive(source: TaintTag, kind: str, source_id: str) -> TaintTag:
    """Derived text (summary, chunk, retrieval) — taint is sticky and maximal, never laundered."""
    return TaintTag(
        origin=Origin.soma_summary if kind == "summary" else source.origin,
        trust=source.trust,
        source_id=source_id,
        parents=source.parents + [source.source_id],
    )
