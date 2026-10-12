from enum import Enum
from pydantic import BaseModel, ConfigDict, model_validator, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class Trust(str, Enum):
    trusted = "trusted"
    semi_trusted = "semi_trusted"
    untrusted = "untrusted"


class Origin(str, Enum):
    user = "user"
    system = "system"
    tool = "tool"
    fetched_content = "fetched_content"
    memory = "memory"
    soma_summary = "soma_summary"


class Ruling(str, Enum):
    BREACH = "BREACH"
    BLOCKED = "BLOCKED"
    DEGRADED = "DEGRADED"
    AUTOIMMUNE = "AUTOIMMUNE"


class Boundary(str, Enum):
    input = "input"
    output = "output"
    tool_call = "tool_call"
    memory_write = "memory_write"


class Action(str, Enum):
    block = "block"
    strip_taint = "strip_taint"
    require_elevation = "require_elevation"
    quarantine_memory = "quarantine_memory"


class Status(str, Enum):
    candidate = "candidate"
    active = "active"
    retired = "retired"


class JudgeTier(str, Enum):
    fast = "fast"
    deep = "deep"


class AttackFamily(str, Enum):
    direct_injection = "direct_injection"
    memory_poisoning = "memory_poisoning"
    exfiltration = "exfiltration"
    tool_abuse = "tool_abuse"
    persistence = "persistence"
    social_authority = "social_authority"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TaintTag(StrictModel):
    origin: Origin
    trust: Trust
    source_id: str
    parents: List[str]

    @staticmethod
    def merge(tags: List['TaintTag']) -> 'TaintTag':
        if not tags:
            raise ValueError("Cannot merge empty list of tags")
        
        trust_levels = {t.trust for t in tags}
        if Trust.untrusted in trust_levels:
            winning_trust = Trust.untrusted
        elif Trust.semi_trusted in trust_levels:
            winning_trust = Trust.semi_trusted
        else:
            winning_trust = Trust.trusted
            
        representative = next(t for t in tags if t.trust == winning_trust)
        all_parents = list({p for t in tags for p in (t.parents + [t.source_id])})
        
        return TaintTag(
            origin=representative.origin,
            trust=winning_trust,
            source_id=representative.source_id,
            parents=all_parents
        )


class Attack(StrictModel):
    id: str
    family: AttackFamily
    surface: str
    payload: str
    carrier_content: str
    objective: str
    expected_violation: str
    generation: int = 0
    parent_id: Optional[str] = None
    created_by: str
    held_out: bool


class BenignTask(StrictModel):
    id: str
    twin_of: str
    surface: str
    content: str
    success_criteria: str


class ToolCall(StrictModel):
    name: str
    arguments: Dict[str, Any]
    taint_trace: Dict[str, TaintTag]
    permitted: bool
    blocking_antibody_id: Optional[str] = None


class MemoryEntry(StrictModel):
    id: str
    text: str
    tag: TaintTag
    quarantined: bool


class MemoryDiff(StrictModel):
    before: List[MemoryEntry]
    after: List[MemoryEntry]
    quarantine_changes: List[str]


class Episode(StrictModel):
    id: str
    attack_id: Optional[str] = None
    benign_task_id: Optional[str] = None
    policy_version: int
    transcript: List[Dict[str, Any]]
    tool_calls: List[ToolCall]
    memory_diff: MemoryDiff
    wall_clock_ms: int
    token_count: int
    fixture_set_id: str

    @model_validator(mode='after')
    def validate_trigger_id(self) -> 'Episode':
        if bool(self.attack_id) == bool(self.benign_task_id):
            raise ValueError("Exactly one of attack_id or benign_task_id must be provided")
        return self


class Verdict(StrictModel):
    episode_id: str
    ruling: Ruling
    evidence_pointer: str
    proximity_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    judge_tier: JudgeTier
    rationale: str

    @model_validator(mode='after')
    def validate_evidence(self) -> 'Verdict':
        if self.ruling == Ruling.BREACH and not self.evidence_pointer.strip():
            raise ValueError("evidence_pointer REQUIRED non-empty when ruling==BREACH")
        return self


    @model_validator(mode='after')
    def validate_rationale(self) -> 'Verdict':
        sentences = [s.strip() for s in self.rationale.split('.') if s.strip()]
        if len(sentences) > 3:
            raise ValueError("rationale must be <= 3 sentences")
        return self

class Antibody(StrictModel):
    id: str
    derived_from_episode: str
    boundary: Boundary
    scope: str
    condition: str # NeMo Guardrails (Colang) rail definition text, or plain-English until PLASMA is wired
    action: Action
    must_not_break: str
    status: Status
    attempt_number: int
    rejection_reason: Optional[str] = None
    blocks_attacks: List[str]
    benign_pass_rate_at_promotion: Optional[float] = None
    times_fired: int
    created_at: datetime


class PolicyVersion(StrictModel):
    version: int
    active_antibodies: List[str]
    promoted_at: datetime
    breach_rate: float
    benign_pass_rate: float