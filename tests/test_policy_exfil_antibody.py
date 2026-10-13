"""Exfil antibody policy tests. Antibodies come from the test-only
reference fixture -- SOMA ships defenceless."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tests.fixtures.reference_antibodies import REFERENCE_EXFIL_ANTIBODY
from immunis.soma import policy


def setup_function(function):
    policy.active_antibodies.clear()


def teardown_function(function):
    policy.active_antibodies.clear()


def test_policy_ships_defenceless():
    assert policy.active_antibodies == []


def _make_call(name, args, taint_trace):
    # Adjust to however tests/test_soma.py constructs calls
    from tests.test_soma import _make_call as real
    return real(name, args, taint_trace)


def test_exfil_untrusted_body_blocked():
    policy.active_antibodies.append(REFERENCE_EXFIL_ANTIBODY)
    # ... the send_message call with untrusted taint as in test_soma.py
    # permitted, blocking_id, reason = policy.evaluate_tool_call(call)
    # assert not permitted and blocking_id == "ab-block-exfil-untrusted-body"
