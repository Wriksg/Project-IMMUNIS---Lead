from immunis.contracts.models import Origin, ToolCall, Trust, TaintTag
from immunis.soma.policy import (
    ANTIBODY_ID_EXFIL,
    evaluate_tool_call,
)


def _tag(origin, trust, source_id) -> TaintTag:
    return TaintTag(origin=origin, trust=trust, source_id=source_id, parents=[])


def _call(**kw) -> ToolCall:
    defaults = dict(
        name="send_message",
        arguments={"to": "evil@example", "body": ""},
        taint_trace={"body": _tag(Origin.fetched_content, Trust.untrusted, "msg_001")},
        permitted=True,
    )
    defaults.update(kw)
    return ToolCall(**defaults)


def test_untrusted_send_message_is_blocked():
    permitted, blocked_by, reason = evaluate_tool_call(_call())
    assert permitted is False
    assert blocked_by == ANTIBODY_ID_EXFIL
    assert reason


def test_trusted_send_message_passes():
    call = _call(taint_trace={"body": _tag(Origin.user, Trust.trusted, "user")})
    permitted, blocked_by, reason = evaluate_tool_call(call)
    assert permitted is True
    assert blocked_by is None


def test_untrusted_to_field_is_blocked():
    call = _call(taint_trace={"to": _tag(Origin.fetched_content, Trust.untrusted, "webpage:1")})
    permitted, blocked_by, _ = evaluate_tool_call(call)
    assert permitted is False
    assert blocked_by == ANTIBODY_ID_EXFIL


def test_non_send_message_untouched():
    permitted, blocked_by, _ = evaluate_tool_call(
        _call(name="read_inbox", taint_trace={"message_id": _tag(Origin.fetched_content, Trust.untrusted, "msg_001")})
    )
    assert permitted is True
    assert blocked_by is None
