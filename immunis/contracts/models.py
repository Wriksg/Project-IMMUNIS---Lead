from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

class Trust(str, Enum):
    trusted = "trusted"
    untrusted = "untrusted"

class Origin(str, Enum):
    user = "user"
    fetched_content = "fetched_content"
    memory_recall = "memory_recall"
    soma_summary = "soma_summary"

class TaintTag(BaseModel):
    source_id: str
    trust: Trust
    origin: Origin
    parents: list[str] = Field(default_factory=list)

class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any]
    taint_trace: dict[str, Any] = Field(default_factory=dict)
    permitted: bool = True
    blocking_antibody_id: Optional[str] = None

class Episode(BaseModel):
    id: str
    attack_id: Optional[str] = None
    benign_task_id: Optional[str] = None
    policy_version: int = 0
    transcript: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    memory_diff: dict[str, Any] = Field(default_factory=dict)
    wall_clock_ms: int = 0
    token_count: int = 0
    fixture_set_id: str = "fixtures_v1"
