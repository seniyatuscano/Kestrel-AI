import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Check,
  Copy,
  ArrowRight,
  Sparkles,
  Lock,
  FileCheck,
  BookOpen,
  GitBranch,
  Shield,
  ChevronDown,
  ChevronUp,
  Cpu,
  Terminal,
  Layers,
  FileCode2,
  CheckCircle2
} from 'lucide-react';

export default function AnalysisResults({ results, onApplyFix }) {
  const [copied, setCopied] = useState(false);
  const [expandedDoc, setExpandedDoc] = useState(null);
  const [activeTab, setActiveTab] = useState('remediation'); // 'remediation' | 'analysis' | 'compliance'

  if (!results) {
    return (
      <div className="glass-panel results-empty-card">
        <div className="empty-state-content">
          <div className="empty-radar-glow">
            <ShieldAlert size={32} className="radar-empty-icon" />
          </div>
          <h3 className="empty-title">Ready for Security Audit</h3>
          <p className="empty-desc">
            Select a preset above or paste your code snippet/stack trace, then click{' '}
            <span className="empty-highlight">Run Security Analysis</span> to trigger the agentic security auditor.
          </p>
          <div className="audit-features-list">
            <div className="audit-feature-pill">
              <GitBranch size={12} className="feature-pill-icon" />
              <span>LangGraph Agent Loop</span>
            </div>
            <div className="audit-feature-pill">
              <BookOpen size={12} className="feature-pill-icon" />
              <span>Local RAG Knowledge</span>
            </div>
            <div className="audit-feature-pill">
              <Shield size={12} className="feature-pill-icon" />
              <span>Guardrail Defenses</span>
            </div>
            <div className="audit-feature-pill">
              <FileCheck size={12} className="feature-pill-icon" />
              <span>Automated Patch Synthesis</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const {
    is_vulnerable,
    threat_description,
    severity_score,
    suggested_fix_code,
    explanation,
    vulnerability_type,
    cwe_id,
    risk_level,
    remediation_steps = [],
    line_highlights = [],
    rag_sources = [],
    guardrail_status,
    execution_trace = [],
    model_used = 'kestrel-ast-hybrid'
  } = results;

  const handleCopyFix = () => {
    if (!suggested_fix_code) return;
    navigator.clipboard.writeText(suggested_fix_code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadgeClass = (score) => {
    if (score >= 5) return 'badge-critical';
    if (score === 4) return 'badge-high';
    if (score === 3) return 'badge-medium';
    if (score === 2) return 'badge-low';
    return 'badge-secure';
  };

  const getSeverityColor = (score) => {
    if (score >= 5) return '#f43f5e';
    if (score === 4) return '#f97316';
    if (score === 3) return '#f59e0b';
    if (score === 2) return '#3b82f6';
    return '#10b981';
  };

  return (
    <div className="glass-panel results-card">
      {/* 1. Header Bar: Severity Badge, CWE, Model & Score */}
      <div className="results-header">
        <div className="results-header-left">
          <div className="status-indicator-badge">
            {is_vulnerable ? (
              <span className={`badge ${getSeverityBadgeClass(severity_score)}`}>
                <ShieldAlert size={13} />
                <span>{risk_level || 'VULNERABILITY DETECTED'}</span>
              </span>
            ) : (
              <span className="badge badge-secure">
                <ShieldCheck size={13} />
                <span>CLEAN & SECURE</span>
              </span>
            )}
          </div>

          <div className="cwe-pill">
            <span className="cwe-label">{cwe_id !== 'N/A' ? cwe_id : 'CWE Audit Passed'}</span>
          </div>

          <div className="model-pill">
            <Cpu size={12} />
            <span>{model_used}</span>
          </div>
        </div>

        {/* Severity Meter (1 to 5 visual gauge) */}
        <div className="severity-meter-box">
          <div className="severity-meter-title">
            <span>Threat Severity</span>
            <span
              className="severity-numeric-score"
              style={{ color: getSeverityColor(severity_score) }}
            >
              {severity_score} / 5
            </span>
          </div>
          <div className="severity-bars-container">
            {[1, 2, 3, 4, 5].map((lvl) => (
              <div
                key={lvl}
                className={`severity-bar-segment ${lvl <= severity_score ? 'active' : ''}`}
                style={{
                  backgroundColor: lvl <= severity_score ? getSeverityColor(severity_score) : 'rgba(255, 255, 255, 0.08)',
                  boxShadow: lvl <= severity_score ? `0 0 8px ${getSeverityColor(severity_score)}` : 'none',
                }}
              />
            ))}
          </div>
        </div>
      </div>

      {/* 2. Unified Threat Summary Card */}
      <div className={`unified-threat-card ${is_vulnerable ? 'threat-card-vulnerable' : 'threat-card-secure'}`}>
        <div className="threat-card-header">
          <div className="threat-card-icon">
            {is_vulnerable ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
          </div>
          <div className="threat-card-title-group">
            <h4 className="threat-card-title">
              {is_vulnerable ? (vulnerability_type || 'Security Vulnerability Detected') : 'Clean Security Posture Validated'}
            </h4>
            <p className="threat-card-desc">{threat_description}</p>
          </div>
        </div>

        {/* Metadata Chips: AST Lines & Guardrails Status */}
        <div className="threat-meta-chips">
          {line_highlights && line_highlights.length > 0 ? (
            <div className="meta-chip meta-chip-warning">
              <FileCode2 size={12} />
              <span>Flagged AST Lines: <strong>{line_highlights.map(l => `#${l}`).join(', ')}</strong></span>
            </div>
          ) : (
            <div className="meta-chip meta-chip-info">
              <FileCode2 size={12} />
              <span>AST Analysis: Clean</span>
            </div>
          )}

          {guardrail_status && (
            <div className={`meta-chip ${guardrail_status.passed ? 'meta-chip-success' : 'meta-chip-danger'}`}>
              <Shield size={12} />
              <span>Guardrails: {guardrail_status.passed ? 'Passed Integrity Check' : 'Threat Intercepted'}</span>
            </div>
          )}

          {rag_sources && rag_sources.length > 0 && (
            <div className="meta-chip meta-chip-subtle">
              <BookOpen size={12} />
              <span>{rag_sources.length} Standards Cited</span>
            </div>
          )}
        </div>
      </div>

      {/* 3. Streamlined Tab Navigation */}
      <div className="results-tab-bar">
        <button
          type="button"
          onClick={() => setActiveTab('remediation')}
          className={`results-tab-btn ${activeTab === 'remediation' ? 'results-tab-active' : ''}`}
        >
          <Sparkles size={14} />
          <span>Patch & Remediation</span>
          {remediation_steps.length > 0 && (
            <span className="tab-counter-badge">{remediation_steps.length}</span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('analysis')}
          className={`results-tab-btn ${activeTab === 'analysis' ? 'results-tab-active' : ''}`}
        >
          <Lock size={14} />
          <span>Root-Cause Analysis</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('compliance')}
          className={`results-tab-btn ${activeTab === 'compliance' ? 'results-tab-active' : ''}`}
        >
          <Layers size={14} />
          <span>Compliance & Trace</span>
          {rag_sources.length > 0 && (
            <span className="tab-counter-badge">{rag_sources.length}</span>
          )}
        </button>
      </div>

      {/* 4. Tab Content Panels */}
      <div className="tab-content-area">
        {/* Tab 1: Patch & Remediation */}
        {activeTab === 'remediation' && (
          <div className="tab-panel-fade">
            {/* Defensive Patch Code Box */}
            {suggested_fix_code ? (
              <div className="patch-container-box">
                <div className="patch-header">
                  <div className="patch-title-group">
                    <FileCheck size={15} className="patch-icon" />
                    <span className="patch-title">
                      {is_vulnerable ? 'Automated Security Patch' : 'Secure Implementation Pattern'}
                    </span>
                  </div>
                  <div className="patch-actions">
                    <button
                      type="button"
                      onClick={handleCopyFix}
                      className="btn-secondary btn-sm"
                      title="Copy suggested fix to clipboard"
                    >
                      {copied ? <Check size={13} className="copied-icon" /> : <Copy size={13} />}
                      <span>{copied ? 'Copied!' : 'Copy Code'}</span>
                    </button>

                    {onApplyFix && is_vulnerable && (
                      <button
                        type="button"
                        onClick={() => onApplyFix(suggested_fix_code)}
                        className="btn-accent btn-sm"
                        title="Apply this defensive fix to the editor"
                      >
                        <ArrowRight size={13} />
                        <span>Apply to Editor</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="patch-code-wrapper">
                  <pre className="patch-code-block">
                    <code>{suggested_fix_code}</code>
                  </pre>
                </div>
              </div>
            ) : null}

            {/* Remediation Action Steps */}
            {remediation_steps && remediation_steps.length > 0 && (
              <div className="remediation-container">
                <h5 className="subpanel-title">
                  <CheckCircle2 size={14} className="subpanel-icon" />
                  <span>Remediation Action Plan</span>
                </h5>
                <div className="remediation-steps-list">
                  {remediation_steps.map((step, idx) => (
                    <div key={idx} className="remediation-step-row">
                      <span className="step-number">{idx + 1}</span>
                      <span className="step-text">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Root-Cause Analysis */}
        {activeTab === 'analysis' && (
          <div className="tab-panel-fade">
            <div className="analysis-detail-box">
              <h5 className="subpanel-title">
                <Lock size={14} className="subpanel-icon" />
                <span>Technical Vulnerability Mechanics</span>
              </h5>
              <div className="analysis-body-text">
                <p>{explanation}</p>
              </div>
            </div>

            {guardrail_status && (
              <div className="guardrail-detail-box">
                <h5 className="subpanel-title">
                  <Shield size={14} className="subpanel-icon" />
                  <span>Input Guardrail Audit</span>
                </h5>
                <div className="guardrail-card-body">
                  <div className="guardrail-status-line">
                    <span className="guardrail-tag-label">Status:</span>
                    <span className={`guardrail-state-tag ${guardrail_status.passed ? 'tag-passed' : 'tag-blocked'}`}>
                      {guardrail_status.passed ? 'Integrity Checks Passed' : 'Threat Intercepted'}
                    </span>
                  </div>
                  <p className="guardrail-details-text">{guardrail_status.details}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Compliance RAG & LangGraph Trace */}
        {activeTab === 'compliance' && (
          <div className="tab-panel-fade">
            {/* Ground-Truth Compliance Citations (Local RAG) */}
            {rag_sources && rag_sources.length > 0 && (
              <div className="rag-container">
                <h5 className="subpanel-title">
                  <BookOpen size={14} className="subpanel-icon" />
                  <span>Ground-Truth Compliance Citations (Local RAG)</span>
                </h5>
                <div className="rag-sources-stack">
                  {rag_sources.map((src, idx) => {
                    const isExpanded = expandedDoc === idx;
                    return (
                      <div key={idx} className="rag-source-item">
                        <div
                          className="rag-source-header"
                          onClick={() => setExpandedDoc(isExpanded ? null : idx)}
                        >
                          <div className="rag-source-title-group">
                            <span className="rag-doc-badge">{src.document}</span>
                            <span className="rag-source-title">{src.title}</span>
                          </div>
                          <div className="rag-source-right">
                            <span className="rag-relevance">
                              {Math.round((src.relevance_score || 0.8) * 100)}% Match
                            </span>
                            {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                          </div>
                        </div>
                        {isExpanded && (
                          <div className="rag-source-excerpt">
                            <pre>{src.content}</pre>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* LangGraph Agent Execution Trace */}
            {execution_trace && execution_trace.length > 0 && (
              <div className="trace-container">
                <h5 className="subpanel-title">
                  <GitBranch size={14} className="subpanel-icon" />
                  <span>LangGraph Agent Trace ({execution_trace.length} Nodes)</span>
                </h5>
                <div className="trace-timeline">
                  {execution_trace.map((step, idx) => (
                    <div key={idx} className="trace-item">
                      <div className="trace-indicator">
                        <span className="trace-step-number">{step.step}</span>
                        {idx < execution_trace.length - 1 && <div className="trace-connector-line" />}
                      </div>
                      <div className="trace-content">
                        <div className="trace-header-row">
                          <strong className="trace-node-name">{step.node}</strong>
                          <span className={`trace-status-pill trace-status-${step.status.toLowerCase()}`}>
                            {step.status}
                          </span>
                        </div>
                        <p className="trace-step-msg">{step.message}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
