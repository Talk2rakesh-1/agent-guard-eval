from __future__ import annotations

from .audit import AuditLogger
from .detector import PromptInjectionDetector
from .models import AnalysisRequest, AnalysisResult, ToolDecision, ToolDecisionRequest
from .policy import ToolPolicyEngine


class GuardService:
    def __init__(
        self, detector: PromptInjectionDetector, policy: ToolPolicyEngine, audit: AuditLogger
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.audit = audit

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        result = self.detector.analyze(request.text, request.source)
        self.audit.record(
            "analysis",
            {
                "content_sha256": result.content_sha256,
                "risk": result.risk.value,
                "score": result.score,
                "action": result.action,
                "rule_ids": [item.rule_id for item in result.findings],
            },
        )
        return result

    def decide_tool(self, request: ToolDecisionRequest) -> ToolDecision:
        decision = self.policy.decide(request)
        self.audit.record(
            "tool_decision",
            {
                "tool_name": request.tool_name,
                "context_risk": request.context_risk.value,
                "allowed": decision.allowed,
                "requires_human_approval": decision.requires_human_approval,
                "policy_id": decision.policy_id,
            },
        )
        return decision
