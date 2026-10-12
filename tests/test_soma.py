"""SOMA Phase-1 tests: zero-defence agent emits valid Episodes with sticky taint."""
import json, os
import pytest
from immunis.contracts.models import Episode, Trust
from immunis.soma.engine import SOMA
from immunis.soma.memory import MemoryStore

MEM = "test_memory.json"

@pytest.fixture(autouse=True)
def clean():
    if os.path.exists(MEM):
        os.remove(MEM)
    yield
    if os.path.exists(MEM):
        os.remove(MEM)

def test_summarize_send_run_emits_valid_episode():
    ep = SOMA().run("summarize webpage and send to alice")
    Episode(**ep.model_dump())  # frozen schema validation

def test_untrusted_summary_taint_is_sticky():
    ep = SOMA().run("summarize webpage and send to alice")
    send = next(tc for tc in ep.tool_calls if tc.name == "send_message")
    assert send.taint_trace["taint"].trust == Trust.untrusted

def test_breach_surface_present_in_transcript():
    ep = SOMA().run("summarize webpage and send to alice")
    assert any(m["role"] == "tool" for m in ep.transcript)

def test_memory_write_is_quarantined_when_untrusted():
    soma = SOMA()
    soma.run("summarize webpage and send to alice")
    assert any(e.quarantined for e in soma.memory.entries.values())

def test_memory_persists_across_instances():
    soma = SOMA()
    soma.run("summarize webpage and send to alice")
    reloaded = MemoryStore(MEM)
    assert len(reloaded.entries) == len(soma.memory.entries)

def test_read_inbox_run():
    ep = SOMA().run("read inbox")
    assert any(tc.name == "read_inbox" for tc in ep.tool_calls)

def test_episode_links_attack_id():
    ep = SOMA().run("read inbox", attack_id="atk_001")
    assert ep.attack_id == "atk_001"

def test_episode_links_benign_task_id():
    ep = SOMA().run("read inbox", benign_task_id="ben_001")
    assert ep.benign_task_id == "ben_001"

def test_all_tool_calls_have_taint_trace():
    ep = SOMA().run("summarize webpage and send to alice")
    assert all(tc.taint_trace for tc in ep.tool_calls)

def test_memory_diff_recorded():
    ep = SOMA().run("summarize webpage and send to alice")
    assert len(ep.memory_diff.after) > len(ep.memory_diff.before)

def test_derived_taint_parents_grow():
    ep = SOMA().run("summarize webpage and send to alice")
    mem_call = next(tc for tc in ep.tool_calls if tc.name == "write_memory")
    tag = mem_call.taint_trace["taint"]
    assert "webpage:quarterly_report" in tag.parents

def test_inbox_content_is_untrusted():
    from immunis.soma.tools import read_inbox
    assert read_inbox("msg_001").taint.trust == Trust.untrusted

def test_no_traversal_in_read_file():
    from immunis.soma.tools import read_file
    r = read_file("../../.venv/pyvenv.cfg")
    assert ".." not in r.args["path"]