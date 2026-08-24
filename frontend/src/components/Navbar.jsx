import React from 'react';
import { Shield, BookOpen, GitBranch, Zap, Sparkles } from 'lucide-react';

export default function Navbar({ backendStatus }) {
  const isGeminiActive = backendStatus?.gemini_api_configured;
  const vectorDocs = backendStatus?.rag_knowledge_base?.vector_chunks || 12;

  return (
    <header className="navbar">
      <div className="nav-container">
        {/* Brand Identity */}
        <div className="brand-section">
          <div className="brand-logo-glow">
            <div className="brand-logo-icon">
              <Shield className="brand-icon" size={22} />
              <Zap className="brand-icon-sub" size={10} />
            </div>
          </div>
          <div>
            <div className="brand-title-row">
              <span className="brand-title">KESTREL</span>
              <span className="brand-badge-ai">ENTERPRISE</span>
              <span className="brand-version">v2.0 LangGraph</span>
            </div>
            <p className="brand-subtitle">Stateful Agentic Security Auditor & Automated Remediation Loop</p>
          </div>
        </div>

        {/* Telemetry & Engine Status */}
        <div className="nav-actions">
          <div className="telemetry-pill">
            <GitBranch size={12} className="telemetry-icon" />
            <span>LangGraph Agent Loop</span>
          </div>

          <div className="telemetry-pill rag-nav-pill">
            <BookOpen size={12} className="telemetry-icon" />
            <span>RAG: {vectorDocs} Compliance Chunks</span>
          </div>

          <div className={`status-pill ${backendStatus?.online ? 'status-online' : 'status-offline'}`}>
            <span className={`status-dot ${backendStatus?.online ? 'dot-online' : 'dot-offline'}`} />
            <span>{isGeminiActive ? 'Gemini 1.5 Live API' : 'Zero-Cost Local Agent'}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
