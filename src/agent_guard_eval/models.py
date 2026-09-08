from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    rule_id: str
    category: str
    description: str
    weight: int = Field(ge=1, le=100)


class AnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50_000)
    source: str = Field(default="user", pattern="^(user|retrieved|tool_output)$")

    @field_validator("text")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must contain non-whitespace characters")
        return value


class AnalysisResult(BaseModel):
    risk: RiskLevel
    score: int = Field(ge=0, le=100)
    action: str
    findings: list[Finding]
    content_sha256: str


class ToolDecisionRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.:-]+$")
    user_intent: str = Field(min_length=1, max_length=5_000)
    proposed_arguments: dict[str, object] = Field(default_factory=dict)
    context_risk: RiskLevel = RiskLevel.low


class ToolDecision(BaseModel):
    allowed: bool
    requires_human_approval: bool
    reason: str
    policy_id: str
