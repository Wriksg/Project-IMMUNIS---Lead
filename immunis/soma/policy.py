"""PLASMA policy hook. Empty = SOMA is fully defenceless."""
from immunis.contracts.models import Antibody, Trust, TaintTag

active_antibodies: list[Antibody] = []   # <- add Antibody objects here only via THYMUS


def quarantine_required(taint: TaintTag) -> bool:
    """Defenceless by default: True only if an ACTIVE memory_write
    quarantine antibody exists AND the text is untrusted."""
    if taint.trust != Trust.untrusted:
        return False

    for ab in active_antibodies:
        v = lambda x: getattr(x, "value", x)
        if (v(ab.status) == "active"
                and v(ab.boundary) == "memory_write"
                and v(ab.action) == "quarantine_memory"):
            return True

    return False