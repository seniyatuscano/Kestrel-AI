import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import PresetsSelector from './components/PresetsSelector';
import CodeEditor from './components/CodeEditor';
import AnalysisResults from './components/AnalysisResults';
import ScanHistory from './components/ScanHistory';
import { analyzeCode, fetchSamples, checkHealth } from './services/api';
import { Shield, Sparkles, CheckCircle, AlertCircle } from 'lucide-react';
import './App.css';

const DEFAULT_CODE_SAMPLE = `import sqlite3

def authenticate_user(username, password):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    
    # Vulnerable: Unsafe string formatting allows SQL Injection (' OR '1'='1)
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    return cursor.fetchone()
`;

const FALLBACK_SAMPLES = [
  {
    id: 'sqli-sample',
    title: 'SQL Injection',
    category: 'Database Security',
    language: 'python',
    description: 'Concatenating unsanitized credentials directly into database query string.',
    code: DEFAULT_CODE_SAMPLE,
  },
  {
    id: 'eval-rce-sample',
    title: 'Remote Code Execution (eval)',
    category: 'Code Execution',
    language: 'python',
    description: 'Executing unvalidated user calculation formulas directly in Python runtime.',
    code: `def calculate_user_formula(payload_str):
    # Vulnerable: Arbitrary expression evaluation allows system compromise
    result = eval(payload_str)
    return {"calculated": result}
`,
  },
  {
    id: 'cmd-injection-sample',
    title: 'Command Injection (os.system)',
    category: 'System Security',
    language: 'python',
    description: 'Invoking shell utility with direct string concatenation from request parameter.',
    code: `import os

def ping_host_diagnostic(target_ip):
    # Vulnerable: Shell metacharacters can execute arbitrary commands
    command = "ping -c 1 " + target_ip
    os.system(command)
`,
  },
  {
    id: 'secrets-sample',
    title: 'Hardcoded Secret Key',
    category: 'Credential Security',
    language: 'python',
    description: 'Production API credentials stored in cleartext source files.',
    code: `import requests

# Vulnerable: Leaked secret key in source control
API_SECRET_KEY = "mock_secret_key_prod_94810294810293840192"

def process_refund(charge_id):
    headers = {"Authorization": f"Bearer {API_SECRET_KEY}"}
    return requests.post(f"https://api.example.com/v1/refunds", headers=headers, json={"charge": charge_id})
`,
  },
  {
    id: 'clean-sample',
    title: 'Secure Parameterized Query',
    category: 'Secure Architecture',
    language: 'python',
    description: 'Safe parameterized SQL query and validation adhering to defensive best practices.',
    code: `import sqlite3
from typing import Optional, Dict

def get_user_by_id(db_conn: sqlite3.Connection, user_id: int) -> Optional[Dict[str, str]]:
    # Secure: Parameterized query prevents SQL injection
    query = "SELECT id, email, created_at FROM accounts WHERE id = ?"
    cursor = db_conn.cursor()
    cursor.execute(query, (user_id,))
    row = cursor.fetchone()
    
    if not row:
        return None
    return {"id": row[0], "email": row[1], "created_at": row[2]}
`,
  },
];

export default function App() {
  const [code, setCode] = useState(DEFAULT_CODE_SAMPLE);
  const [language, setLanguage] = useState('python');
  const [contextType, setContextType] = useState('snippet');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [samples, setSamples] = useState(FALLBACK_SAMPLES);
  const [history, setHistory] = useState([]);
  const [backendStatus, setBackendStatus] = useState({ online: false });
  const [toast, setToast] = useState(null);

  // Show temporary toast message
  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3500);
  };

  // Poll backend health and fetch presets
  useEffect(() => {
    const initBackend = async () => {
      try {
        const health = await checkHealth();
        setBackendStatus(health || { online: true });
        const fetchedSamples = await fetchSamples();
        if (fetchedSamples && fetchedSamples.length > 0) {
          setSamples(fetchedSamples);
        }
      } catch (err) {
        setBackendStatus({ online: false });
      }
    };

    initBackend();
    const interval = setInterval(initBackend, 10000);
    return () => clearInterval(interval);
  }, []);

  // Handle trigger analysis
  const handleAnalyze = async () => {
    if (!code.trim()) {
      showToast('Please enter a code snippet or stack trace first.', 'warning');
      return;
    }

    setIsLoading(true);
    try {
      const data = await analyzeCode(code, language, contextType);
      setResults(data);

      // Add to session history
      const historyItem = {
        id: Date.now().toString(),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        title: data.vulnerability_type !== 'None (Clean)' && data.vulnerability_type !== 'None'
          ? data.vulnerability_type
          : 'Clean Code Audit',
        codeSnippet: code,
        response: data,
      };
      setHistory((prev) => [historyItem, ...prev.slice(0, 9)]);

      if (data.is_vulnerable) {
        showToast(`Audit Complete: ${data.risk_level} severity flaw identified (${data.severity_score}/5).`, 'warning');
      } else {
        showToast('Audit Complete: No immediate vulnerabilities found. Code is secure!', 'success');
      }
    } catch (err) {
      showToast(err.message || 'Failed to connect to backend engine.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Preset Selection
  const handleSelectSample = (sample) => {
    setCode(sample.code);
    setLanguage(sample.language || 'python');
    setContextType(sample.id === 'stack-trace-sample' ? 'stack_trace' : 'snippet');
    showToast(`Loaded preset: "${sample.title}"`, 'info');
  };

  // Apply suggested fix into editor
  const handleApplyFix = (fixCode) => {
    setCode(fixCode);
    showToast('Applied automated security patch to the code editor.', 'success');
  };

  // Restore past scan from history
  const handleSelectHistory = (item) => {
    setCode(item.codeSnippet);
    setResults(item.response);
    showToast(`Restored scan: "${item.title}"`, 'info');
  };

  const handleClearHistory = () => {
    setHistory([]);
    showToast('Audit history cleared.', 'info');
  };

  const handleClearEditor = () => {
    setCode('');
    setResults(null);
  };

  return (
    <div className="app-container">
      {/* Navigation Header */}
      <Navbar backendStatus={backendStatus} />

      {/* Main Content Area */}
      <main className="main-content">
        {/* Compact Hero Banner */}
        <section className="hero-banner">
          <h1 className="hero-title">
            Zero-Cost AI Code Security & <span className="hero-highlight">Automated Remediation</span>
          </h1>
          <p className="hero-description">
            Audit source code and stack traces for injection vectors, dangerous execution primitives, and leaked secrets.
          </p>
        </section>

        {/* Sleek Presets Bar */}
        <PresetsSelector
          samples={samples}
          onSelectSample={handleSelectSample}
          currentCode={code}
        />

        {/* Two-Column Audit Workbench */}
        <div className="audit-grid">
          {/* Left Column: Code Editor */}
          <CodeEditor
            code={code}
            setCode={setCode}
            language={language}
            setLanguage={setLanguage}
            contextType={contextType}
            setContextType={setContextType}
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            onClear={handleClearEditor}
          />

          {/* Right Column: Structured Results */}
          <AnalysisResults
            results={results}
            onApplyFix={handleApplyFix}
          />
        </div>

        {/* Audit History Drawer */}
        <ScanHistory
          history={history}
          onSelectHistory={handleSelectHistory}
          onClearHistory={handleClearHistory}
        />
      </main>

      {/* Toast Notification */}
      {toast && (
        <div className="toast-banner">
          {toast.type === 'success' ? (
            <CheckCircle size={15} color="#10b981" />
          ) : toast.type === 'warning' || toast.type === 'error' ? (
            <AlertCircle size={15} color="#f43f5e" />
          ) : (
            <Sparkles size={15} color="#06b6d4" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-container">
          <div>
            <strong>Kestrel AI Enterprise</strong> — Autonomous Code Security & Automated Patch Synthesis.
          </div>
          <div className="footer-links">
            <span className="footer-link">AST Engine</span>
            <span className="footer-link">CWE Taxonomy</span>
            <span className="footer-link">Zero-Cost Architecture</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
