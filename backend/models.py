from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Payload sent by the client containing code or stack trace to audit."""
    code: str = Field(..., description="The code snippet or stack trace text to analyze.")
    language: Optional[str] = Field("python", description="Programming language or context type.")
    context_type: Optional[str] = Field("snippet", description="Type of input: 'snippet' or 'stack_trace'.")


class RAGSourceCitation(BaseModel):
    """Compliance documentation standard cited as ground-truth."""
    chunk_id: str = Field(default="")
    document: str = Field(default="")
    title: str = Field(default="")
    content: str = Field(default="")
    relevance_score: float = Field(default=0.0)


class GuardrailStatus(BaseModel):
    """Telemetry detailing pre-execution security guardrail checks."""
    passed: bool = Field(default=True)
    threat_level: str = Field(default="Passed")
    risk_score: float = Field(default=0.0)
    violations: List[str] = Field(default_factory=list)
    details: str = Field(default="All checks passed cleanly.")
    checks_performed: List[str] = Field(default_factory=list)


class ExecutionTraceStep(BaseModel):
    """Stateful agent execution step telemetry."""
    step: int
    node: str
    status: str
    message: str


class AnalysisResponse(BaseModel):
    """Structured response schema for security analysis."""
    is_vulnerable: bool = Field(..., description="True if any security risks or vulnerabilities were detected.")
    threat_description: str = Field(..., description="Concise summary of the identified threat or security posture.")
    severity_score: int = Field(..., ge=1, le=5, description="Threat severity rating from 1 (Safe/Minimal) to 5 (Critical).")
    suggested_fix_code: str = Field(..., description="Remediated code snippet or safe pattern implementation.")
    explanation: str = Field(..., description="Comprehensive technical explanation and security analysis.")
    vulnerability_type: str = Field(default="None", description="Vulnerability category (e.g. SQL Injection, RCE).")
    cwe_id: str = Field(default="N/A", description="Common Weakness Enumeration ID (e.g. CWE-89, CWE-78).")
    risk_level: str = Field(default="Secure", description="Human-readable risk tier (Secure, Low, Medium, High, Critical).")
    remediation_steps: List[str] = Field(default_factory=list, description="Step-by-step guidance to remediate the risk.")
    line_highlights: List[int] = Field(default_factory=list, description="Line numbers where potential risks were detected.")
    
    # Enterprise Modules
    rag_sources: List[RAGSourceCitation] = Field(default_factory=list, description="Compliance ground truth sources used.")
    guardrail_status: Optional[GuardrailStatus] = Field(default=None, description="Input guardrail verification details.")
    execution_trace: List[ExecutionTraceStep] = Field(default_factory=list, description="LangGraph agent node execution traces.")
    model_used: str = Field(default="kestrel-ast-hybrid", description="AI reasoning model or engine utilized.")


class SampleSnippet(BaseModel):
    """Schema for pre-packaged vulnerability demo samples."""
    id: str
    title: str
    category: str
    language: str
    code: str
    description: str
