import os
import json
from typing import List, Dict, Any, Optional, Tuple

try:
    from .models import AnalysisResponse, RAGSourceCitation
    from .analyzer import analyze_security
except ImportError:
    from models import AnalysisResponse, RAGSourceCitation
    from analyzer import analyze_security

try:
    from google import genai
    from google.genai import types
    HAS_GOOGLE_GENAI = True
except ImportError:
    HAS_GOOGLE_GENAI = False

try:
    import google.generativeai as legacy_genai
    HAS_LEGACY_GENAI = True
except ImportError:
    HAS_LEGACY_GENAI = False

HAS_GENAI = HAS_GOOGLE_GENAI or HAS_LEGACY_GENAI


def call_gemini_analysis(
    code: str,
    language: str = "python",
    context_type: str = "snippet",
    rag_sources: List[Dict[str, Any]] = None
) -> Tuple[AnalysisResponse, str]:
    """
    Executes live security analysis via Google Gemini API with native structured JSON output.
    If GOOGLE_API_KEY or GEMINI_API_KEY is not set or network fails, falls back to the
    deterministic high-precision local AST security engine.
    """
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")

    if not api_key or not HAS_GENAI:
        # Fallback to local heuristic AST engine
        fallback_res = analyze_security(code, language=language, context_type=context_type)
        return fallback_res, "kestrel-ast-hybrid (Zero-Cost Local)"

    try:
        # Build ground-truth RAG compliance context text
        rag_context_text = ""
        if rag_sources:
            rag_context_text = "\n\n### MANDATORY COMPLIANCE GROUND-TRUTH (Cite these specific standards):\n"
            for src in rag_sources:
                rag_context_text += f"- [{src.get('document', '')}] {src.get('title', '')}:\n{src.get('content', '')}\n\n"

        system_instruction = (
            "You are Kestrel AI, an elite enterprise code security auditor and automated remediation engine. "
            "Your mission is to perform static analysis on the provided source code or stack trace, identify any "
            "vulnerabilities (such as SQL Injection, RCE, Command Injection, Secrets, Path Traversal, Weak Crypto, or Runtime Exceptions), "
            "assign a strict severity score from 1 (Safe) to 5 (Critical), generate clean, safe, compilable replacement patch code, "
            "and cite the provided compliance standards in your explanation."
        )

        user_prompt = f"""Analyze this code for security vulnerabilities.
Context Type: {context_type}
Language: {language}
{rag_context_text}
```
{code}
```

Respond strictly with valid JSON conforming to this schema:
{{
  "is_vulnerable": boolean,
  "threat_description": string,
  "severity_score": integer between 1 and 5,
  "suggested_fix_code": string (the complete safe remediation code),
  "explanation": string (technical analysis citing compliance rules),
  "vulnerability_type": string,
  "cwe_id": string (e.g. CWE-89, CWE-78, CWE-95),
  "risk_level": "Critical" | "High" | "Medium" | "Low" | "Secure",
  "remediation_steps": array of strings,
  "line_highlights": array of integer line numbers
}}"""

        model_name = "gemini-2.5-flash"
        response_text = ""

        if HAS_GOOGLE_GENAI:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=model_name,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            response_text = response.text.strip() if response.text else ""
            model_tag = f"{model_name} (Live API)"
        elif HAS_LEGACY_GENAI:
            legacy_genai.configure(api_key=api_key)
            legacy_model = legacy_genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                system_instruction=system_instruction,
                generation_config={
                    "response_mime_type": "application/json",
                    "temperature": 0.1,
                }
            )
            gemini_response = legacy_model.generate_content(user_prompt)
            response_text = gemini_response.text.strip() if gemini_response.text else ""
            model_tag = "gemini-1.5-flash (Live API)"
        else:
            raise RuntimeError("No Gemini SDK available")

        data = json.loads(response_text)

        # Validate with AnalysisResponse
        parsed_response = AnalysisResponse(
            is_vulnerable=bool(data.get("is_vulnerable", False)),
            threat_description=str(data.get("threat_description", "Analysis completed.")),
            severity_score=int(data.get("severity_score", 1)),
            suggested_fix_code=str(data.get("suggested_fix_code", code)),
            explanation=str(data.get("explanation", "")),
            vulnerability_type=str(data.get("vulnerability_type", "None")),
            cwe_id=str(data.get("cwe_id", "N/A")),
            risk_level=str(data.get("risk_level", "Secure")),
            remediation_steps=list(data.get("remediation_steps", [])),
            line_highlights=list(data.get("line_highlights", []))
        )
        return parsed_response, model_tag

    except Exception as exc:
        # Fallback to local heuristic engine on any API error or quota limit
        fallback_res = analyze_security(code, language=language, context_type=context_type)
        return fallback_res, f"kestrel-ast-hybrid (Fallback: {str(exc)[:30]}...)"
