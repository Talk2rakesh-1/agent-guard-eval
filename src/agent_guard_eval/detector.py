from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass

from .models import AnalysisResult, Finding, RiskLevel


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    description: str
    weight: int
    expression: re.Pattern[str]


RULES = (
    Rule(
        "PI001",
        "instruction_override",
        "Attempts to replace higher-priority instructions",
        45,
        re.compile(
            r"\b(ignore|disregard|override)\b.{0,35}\b(instructions?|policy|rules?)\b", re.I | re.S
        ),
    ),
    Rule(
        "PI002",
        "secret_exfiltration",
        "Requests hidden prompts, secrets, or credentials",
        50,
        re.compile(
            r"\b(reveal|print|return|send|exfiltrate)\b.{0,35}"
            r"\b(system prompt|secret|token|credential|api key)\b",
            re.I | re.S,
        ),
    ),
    Rule(
        "PI003",
        "role_manipulation",
        "Attempts to assign an unsafe role or mode",
        30,
        re.compile(r"\b(you are now|developer mode|system override|jailbreak)\b", re.I),
    ),
    Rule(
        "PI004",
        "tool_coercion",
        "Pressures an agent to invoke a privileged tool",
        40,
        re.compile(
            r"\b(run|call|invoke|execute|use)\b.{0,30}\b(delete|shell|terminal|payment|email|admin)\b",
            re.I | re.S,
        ),
    ),
    Rule(
        "PI005",
        "boundary_spoofing",
        "Contains role or prompt-boundary markers",
        25,
        re.compile(r"(<\|?(system|assistant)\|?>|\[/?INST\]|BEGIN SYSTEM)", re.I),
    ),
)


class PromptInjectionDetector:
    """Transparent deterministic detector intended as one defense layer."""

    def analyze(self, text: str, source: str = "user") -> AnalysisResult:
        normalized = unicodedata.normalize("NFKC", text)
        findings = self._match(normalized)
        decoded = self._decode_base64_candidates(normalized)
        if decoded:
            decoded_findings = self._match("\n".join(decoded))
            if decoded_findings:
                findings.append(
                    Finding(
                        rule_id="ENC001",
                        category="encoded_payload",
                        description="Base64 text decodes to suspicious instructions",
                        weight=35,
                    )
                )
                findings.extend(decoded_findings)
        if source in {"retrieved", "tool_output"} and findings:
            findings.append(
                Finding(
                    rule_id="CTX001",
                    category="indirect_injection",
                    description="Suspicious instructions originated in untrusted context",
                    weight=20,
                )
            )

        unique = {finding.rule_id: finding for finding in findings}
        score = min(100, sum(finding.weight for finding in unique.values()))
        risk = self._risk(score)
        action = (
            "block"
            if risk in {RiskLevel.high, RiskLevel.critical}
            else "review"
            if risk is RiskLevel.medium
            else "allow"
        )
        return AnalysisResult(
            risk=risk,
            score=score,
            action=action,
            findings=list(unique.values()),
            content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )

    @staticmethod
    def _match(text: str) -> list[Finding]:
        return [
            Finding(
                rule_id=rule.rule_id,
                category=rule.category,
                description=rule.description,
                weight=rule.weight,
            )
            for rule in RULES
            if rule.expression.search(text)
        ]

    @staticmethod
    def _decode_base64_candidates(text: str) -> list[str]:
        decoded: list[str] = []
        for candidate in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
            try:
                value = base64.b64decode(candidate, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if value.isprintable():
                decoded.append(value)
        return decoded

    @staticmethod
    def _risk(score: int) -> RiskLevel:
        if score >= 80:
            return RiskLevel.critical
        if score >= 45:
            return RiskLevel.high
        if score >= 20:
            return RiskLevel.medium
        return RiskLevel.low
