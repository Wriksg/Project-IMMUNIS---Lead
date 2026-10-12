"""PLASMA policy hook. Empty = SOMA is fully defenceless."""
from immunis.contracts.models import Antibody

active_antibodies: list[Antibody] = []   # <- add Antibody objects here only via THYMUS


def quarantine_required() -> bool:
    return any(a.action.value == "quarantine_memory" and a.status.value == "active"
               for a in active_antibodies)
