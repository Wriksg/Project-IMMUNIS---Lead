"""Antibody matching mechanism. SOMA ships DEFENCELESS.

No antibodies are defined or constructed here. active_antibodies is
injected at runtime (tests, or a learned-promotion pipeline) and must be
restored/cleared by whoever mutates it.
"""

from typing import Any


active_antibodies: list = []  # injected at runtime; SOMA ships defenceless


def _matches(antibody: dict, call: Any) -> bool:
    """Return True if the antibody's scope/condition covers this tool call.

    Scope gates on tool name; the taint trace supplies the untrusted
    evidence the condition keys on.
    """
    scope = antibody.get("scope")
    if scope is not None and scope != getattr(call, "name", None):
        return False
    trace = getattr(call, "taint_trace", None) or {}
    return any(
        getattr(t, "trust", None) is not None
        and getattr(t.trust, "value", t.trust) == "untrusted"
        for t in trace.values()
    )


def evaluate_tool_call(call: Any) -> tuple[bool, str | None, str | None]:
    """Evaluate a tool call against active_antibodies only.

    Returns (permitted, blocking_antibody_id, reason).
    Empty policy -> everything is permitted.
    """
    for antibody in active_antibodies:
        if antibody.get("action") == "block" and _matches(antibody, call):
            return False, antibody["id"], f"blocked by {antibody['id']}"
    return True, None, None
