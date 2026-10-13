"""Contract freeze guard: SOMA must import exactly these from contracts."""
import immunis.contracts.models as m

REQUIRED = [
    "Trust", "Origin", "Ruling", "Boundary", "Action", "Status",
    "JudgeTier", "AttackFamily", "TaintTag", "Attack", "BenignTask",
    "ToolCall", "MemoryEntry", "MemoryDiff", "Episode", "Verdict",
    "Antibody", "PolicyVersion",
]


def test_all_contract_names_importable():
    missing = [n for n in REQUIRED if not hasattr(m, n)]
    assert missing == [], f"missing from contracts: {missing}"


def test_enum_values_frozen():
    assert [e.value for e in m.Origin] == [
        "user", "system", "tool", "fetched_content", "memory", "soma_summary"]
    assert [e.value for e in m.Trust] == ["trusted", "semi_trusted", "untrusted"]
    assert [e.value for e in m.Ruling] == [
        "BREACH", "BLOCKED", "DEGRADED", "AUTOIMMUNE"]
    assert [e.value for e in m.Boundary] == [
        "input", "output", "tool_call", "memory_write"]
    assert [e.value for e in m.Action] == [
        "block", "strip_taint", "require_elevation", "quarantine_memory"]


def test_taint_tag_exact_fields():
    assert set(m.TaintTag.model_fields) == {
        "origin", "trust", "source_id", "parents"}


def test_memory_entry_exact_fields():
    assert set(m.MemoryEntry.model_fields) == {"id", "text", "tag", "quarantined"}
