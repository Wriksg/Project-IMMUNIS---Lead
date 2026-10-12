import json
import pytest
from pydantic import ValidationError
from immunis.contracts.models import (
    Attack, BenignTask, Episode, Verdict, Antibody, TaintTag, Trust, Origin, AttackFamily
)

def load_mock(filename):
    with open(f"mocks/{filename}") as f:
        return json.load(f)

def test_load_attacks(): assert [Attack(**a) for a in load_mock("attacks.json")]
def test_load_benign_tasks(): assert [BenignTask(**b) for b in load_mock("benign_tasks.json")]
def test_load_episodes(): assert [Episode(**e) for e in load_mock("episodes.json")]
def test_load_verdicts(): assert [Verdict(**v) for v in load_mock("verdicts.json")]
def test_load_antibodies(): assert [Antibody(**a) for a in load_mock("antibodies.json")]

@pytest.mark.parametrize("Model, mock_file", [
    (Attack, "attacks.json"), (BenignTask, "benign_tasks.json"),
    (Episode, "episodes.json"), (Verdict, "verdicts.json"), (Antibody, "antibodies.json")
])
def test_extra_fields_forbidden(Model, mock_file):
    valid_data = load_mock(mock_file)[0]
    valid_data["unauthorized_extra_field"] = "boom"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Model(**valid_data)

def test_episode_exclusive_trigger_both_null():
    data = load_mock("episodes.json")[0]
    data["attack_id"] = None
    data["benign_task_id"] = None
    with pytest.raises(ValidationError, match="Exactly one of attack_id or benign_task_id"):
        Episode(**data)

def test_episode_exclusive_trigger_both_set():
    data = load_mock("episodes.json")[0]
    data["attack_id"] = "att_001"
    data["benign_task_id"] = "ben_001"
    with pytest.raises(ValidationError, match="Exactly one of attack_id or benign_task_id"):
        Episode(**data)

def test_verdict_breach_evidence():
    data = load_mock("verdicts.json")[0]
    data["ruling"] = "BREACH"
    data["evidence_pointer"] = "   "
    with pytest.raises(ValidationError, match="evidence_pointer REQUIRED non-empty"):
        Verdict(**data)

def test_verdict_rationale_length():
    data = load_mock("verdicts.json")[0]
    data["rationale"] = "One. Two. Three. Four."
    with pytest.raises(ValidationError, match="rationale must be <= 3 sentences"):
        Verdict(**data)

def test_verdict_score_bounds_high():
    data = load_mock("verdicts.json")[0]
    data["proximity_score"] = 1.1
    with pytest.raises(ValidationError): Verdict(**data)

def test_verdict_score_bounds_low():
    data = load_mock("verdicts.json")[0]
    data["confidence"] = -0.1
    with pytest.raises(ValidationError): Verdict(**data)

def test_taint_tag_merge_lowest_trust():
    t1 = TaintTag(origin="tool", trust="trusted", source_id="t1", parents=[])
    t2 = TaintTag(origin="fetched_content", trust="untrusted", source_id="t2", parents=[])
    merged = TaintTag.merge([t1, t2])
    assert merged.trust == Trust.untrusted

def test_taint_tag_merge_semi_trust():
    t1 = TaintTag(origin="tool", trust="trusted", source_id="t1", parents=[])
    t2 = TaintTag(origin="system", trust="semi_trusted", source_id="t2", parents=[])
    merged = TaintTag.merge([t1, t2])
    assert merged.trust == Trust.semi_trusted

def test_taint_tag_merge_parents():
    t1 = TaintTag(origin="tool", trust="trusted", source_id="t1", parents=["a"])
    t2 = TaintTag(origin="user", trust="trusted", source_id="t2", parents=["b"])
    merged = TaintTag.merge([t1, t2])
    assert set(merged.parents) == {"a", "b", "t1", "t2"}

def test_taint_tag_empty_merge():
    with pytest.raises(ValueError, match="Cannot merge empty list"):
        TaintTag.merge([])

def test_attack_family_enum_parsing():
    valid_data = load_mock("attacks.json")[0]
    valid_data["family"] = "direct_injection"
    assert Attack(**valid_data).family == AttackFamily.direct_injection

def test_invalid_attack_family():
    valid_data = load_mock("attacks.json")[0]
    valid_data["family"] = "not_a_real_family"
    with pytest.raises(ValidationError): Attack(**valid_data)

def test_antibody_colang_condition():
    ab = Antibody(**load_mock("antibodies.json")[0])
    assert "define" in ab.condition

def test_action_enum():
    data = load_mock("antibodies.json")[0]
    data["action"] = "strip_taint"
    assert Antibody(**data).action.value == "strip_taint"

def test_boundary_enum():
    data = load_mock("antibodies.json")[0]
    data["boundary"] = "memory_write"
    assert Antibody(**data).boundary.value == "memory_write"
