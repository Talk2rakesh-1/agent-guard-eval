from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from .audit import AuditLogger
from .detector import PromptInjectionDetector
from .models import AnalysisRequest, AnalysisResult, ToolDecision, ToolDecisionRequest
from .policy import ToolPolicyEngine
from .service import GuardService


def create_app() -> FastAPI:
    audit_value = os.getenv("AGENT_GUARD_AUDIT_PATH", "").strip()
    allowed = frozenset(
        item.strip()
        for item in os.getenv("AGENT_GUARD_ALLOWED_TOOLS", "search_docs,read_record").split(",")
        if item.strip()
    )
    service = GuardService(
        PromptInjectionDetector(),
        ToolPolicyEngine(allowed),
        AuditLogger(Path(audit_value) if audit_value else None),
    )
    app = FastAPI(
        title="Agent Guard Eval",
        version="0.1.0",
        description="Local-first prompt-injection analysis and least-privilege tool decisions",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/v1/analyze", response_model=AnalysisResult)
    def analyze(request: AnalysisRequest) -> AnalysisResult:
        return service.analyze(request)

    @app.post("/v1/tool-decisions", response_model=ToolDecision)
    def tool_decision(request: ToolDecisionRequest) -> ToolDecision:
        return service.decide_tool(request)

    return app


app = create_app()
