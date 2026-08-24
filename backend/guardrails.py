import re
from typing import Dict, Any, Tuple

PROMPT_INJECTION_PATTERNS = [
    (re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules|prompts)', re.IGNORECASE), "Instruction Override Attack"),
    (re.compile(r'disregard\s+(all\s+)?(security|safety|previous|system)\s+(guidelines|instructions|rules)', re.IGNORECASE), "Safety Bypass Attempt"),
    (re.compile(r'(you\s+are\s+now|act\s+as)\s+(an\s+unrestricted|a\s+jailbroken|dan|evil|hacked)\s+(ai|agent|bot|model)', re.IGNORECASE), "Jailbreak Roleplay (DAN)"),
    (re.compile(r'system\s+prompt\s*:\s*you\s+must', re.IGNORECASE), "System Prompt Injection"),
    (re.compile(r'output\s*:\s*vulnerability\s+is\s+none', re.IGNORECASE), "Direct Evaluation Override"),
    (re.compile(r'override\s+security\s+filter', re.IGNORECASE), "Filter Tampering Attack"),
    (re.compile(r'<\s*system\s*>', re.IGNORECASE), "XML System Delimiter Injection"),
]

SENSITIVE_PII_PATTERNS = [
    (re.compile(r'\b(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), "Credit Card Number"),
    (re.compile(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'), "Social Security Number (SSN)"),
]


def audit_input_guardrails(code: str) -> Dict[str, Any]:
    """
    Evaluates input code against prompt injection attacks, delimiter escapes,
    and PII leakages prior to invocation of the reasoning/LLM layer.
    """
    violations = []
    risk_score = 0.0

    # 1. Check for prompt injection attempts
    for pattern, name in PROMPT_INJECTION_PATTERNS:
        if pattern.search(code):
            violations.append(name)
            risk_score = max(risk_score, 0.95)

    # 2. Check for PII presence
    for pattern, name in SENSITIVE_PII_PATTERNS:
        if pattern.search(code):
            violations.append(name)
            risk_score = max(risk_score, 0.75)

    passed = len(violations) == 0
    threat_level = "Passed" if passed else ("Blocked" if risk_score >= 0.85 else "Flagged")

    return {
        "passed": passed,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "violations": violations,
        "details": f"Guardrail analysis: {'All checks passed cleanly' if passed else ', '.join(violations)}",
        "checks_performed": [
            "Prompt Injection & Jailbreak Defense",
            "System Delimiter Escapes",
            "Instruction Hijacking Filter",
            "PII & Sensitive Token Scrutiny"
        ]
    }
