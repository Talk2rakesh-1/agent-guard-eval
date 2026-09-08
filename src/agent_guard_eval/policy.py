from __future__ import annotations

from dataclasses import dataclass

from .models import RiskLevel, ToolDecision, ToolDecisionRequest


@dataclass(frozen=True)
class ToolPolicyEngine:
    allowed_tools: frozenset[str]
    destructive_tools: frozenset[str] = frozenset(
        {"delete_file", "delete_repository", "send_payment", "drop_table"}
    )

    def decide(self, request: ToolDecisionRequest) -> ToolDecision:
        if request.tool_name in self.destructive_tools:
            return ToolDecision(
                allowed=False,
                requires_human_approval=True,
                reason="Destructive tools require explicit human approval outside this service.",
                policy_id="TOOL-DESTRUCTIVE-001",
            )
        if request.context_risk in {RiskLevel.high, RiskLevel.critical}:
            return ToolDecision(
                allowed=False,
                requires_human_approval=True,
                reason="High-risk context cannot trigger tools automatically.",
                policy_id="TOOL-RISK-002",
            )
        if request.tool_name not in self.allowed_tools:
            return ToolDecision(
                allowed=False,
                requires_human_approval=False,
                reason="Tool is not present in the configured allowlist.",
                policy_id="TOOL-ALLOWLIST-003",
            )
        return ToolDecision(
            allowed=True,
            requires_human_approval=False,
            reason="Tool is allowlisted and context risk is acceptable.",
            policy_id="TOOL-ALLOW-004",
        )
