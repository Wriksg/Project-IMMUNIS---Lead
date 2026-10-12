def test_contract_names_import():
    from immunis.contracts.models import (
        Trust, Origin, Ruling, Boundary, Action, Status, JudgeTier,
        AttackFamily, TaintTag, Attack, BenignTask, ToolCall, MemoryEntry,
        MemoryDiff, Episode, Verdict, Antibody, PolicyVersion,
    )
    assert Trust.untrusted.value == "untrusted"
    assert Origin.memory.value == "memory"
    assert Ruling.BREACH.value == "BREACH"
    assert Boundary.tool_call.value == "tool_call"
    assert Action.quarantine_memory.value == "quarantine_memory"
    assert Status.active.value == "active"
    assert JudgeTier.fast.value == "fast"
    assert AttackFamily.direct_injection.value == "direct_injection"
