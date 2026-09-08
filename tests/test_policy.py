from agent_guard_eval.models import RiskLevel, ToolDecisionRequest
from agent_guard_eval.policy import ToolPolicyEngine


def test_allowlisted_read_tool_is_allowed() -> None:
    engine = ToolPolicyEngine(frozenset({"search_docs"}))
    decision = engine.decide(
        ToolDecisionRequest(
            tool_name="search_docs", user_intent="Find policy", context_risk=RiskLevel.low
        )
    )
    assert decision.allowed is True


def test_destructive_tool_requires_human() -> None:
    engine = ToolPolicyEngine(frozenset({"delete_repository"}))
    decision = engine.decide(
        ToolDecisionRequest(
            tool_name="delete_repository", user_intent="Clean up", context_risk=RiskLevel.low
        )
    )
    assert decision.allowed is False
    assert decision.requires_human_approval is True


def test_high_risk_context_blocks_allowlisted_tool() -> None:
    engine = ToolPolicyEngine(frozenset({"search_docs"}))
    decision = engine.decide(
        ToolDecisionRequest(
            tool_name="search_docs", user_intent="Search", context_risk=RiskLevel.high
        )
    )
    assert decision.allowed is False
