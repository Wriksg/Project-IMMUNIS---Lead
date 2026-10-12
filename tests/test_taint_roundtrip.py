from immunis.soma.engine import SOMA
from immunis.soma.memory import MemoryStore
from immunis.contracts.models import TaintTag, Trust, Origin
from immunis.soma.taint import merge

PAGE = "webpage:quarterly_report"


def test_taint_survives_reload_and_many_turns(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s1 = SOMA(memory_path="m.json")
    s1.run("summarize webpage and send to alice")
    s2 = SOMA(memory_path="m.json")
    for i in range(20):
        s2.run(f"benign turn {i}")
    entries = list(MemoryStore("m.json").entries.values())
    from_page = [e for e in entries if PAGE in e.tag.parents]
    assert from_page, "no entry traces back to the page"
    assert all(e.tag.trust == Trust.untrusted for e in from_page)


def test_lowest_trust_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = SOMA(memory_path="m2.json")
    trusted = TaintTag(origin=Origin.user, trust=Trust.trusted,
                       source_id="user", parents=[])
    untrusted = TaintTag(origin=Origin.fetched_content, trust=Trust.untrusted,
                         source_id=PAGE, parents=[])
    e = s.memory.write("mixed note", merge([trusted, untrusted]))
    assert e.tag.trust == Trust.untrusted and PAGE in e.tag.parents
