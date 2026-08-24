import React, { useRef } from 'react';
import { Play, Trash2, Code2, TerminalSquare, Sparkles } from 'lucide-react';

export default function CodeEditor({
  code,
  setCode,
  language,
  setLanguage,
  contextType,
  setContextType,
  onAnalyze,
  isLoading,
  onClear,
}) {
  const textareaRef = useRef(null);
  const lineNumbersRef = useRef(null);

  // Compute line numbers
  const lines = code.split('\n');
  const lineCount = Math.max(lines.length, 1);
  const lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1);

  // Sync scroll between line numbers and textarea
  const handleScroll = () => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  // Keyboard shortcut: Cmd+Enter or Ctrl+Enter to trigger analysis
  const handleKeyDown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!isLoading && code.trim()) {
        onAnalyze();
      }
    }
  };

  return (
    <div className="glass-panel editor-card">
      {/* Editor Header Bar */}
      <div className="editor-header">
        <div className="editor-tabs">
          <button
            type="button"
            className={`editor-tab ${contextType === 'snippet' ? 'editor-tab-active' : ''}`}
            onClick={() => setContextType('snippet')}
          >
            <Code2 size={14} />
            <span>Code Snippet</span>
          </button>
          <button
            type="button"
            className={`editor-tab ${contextType === 'stack_trace' ? 'editor-tab-active' : ''}`}
            onClick={() => setContextType('stack_trace')}
          >
            <TerminalSquare size={14} />
            <span>Stack Trace</span>
          </button>
        </div>

        <div className="editor-controls">
          <div className="language-badge">
            <span className="lang-indicator" />
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="lang-select"
              aria-label="Programming Language"
            >
              <option value="python">Python</option>
              <option value="javascript">JavaScript / Node</option>
              <option value="bash">Bash / Shell</option>
              <option value="sql">SQL Query</option>
            </select>
          </div>

          <button
            type="button"
            onClick={onClear}
            className="btn-icon"
            title="Clear editor code"
            disabled={!code}
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Editor Main Content Area */}
      <div className="editor-body-wrapper">
        {isLoading && <div className="scanning-bar" />}
        <div className="editor-container">
          {/* Line Numbers */}
          <div className="line-numbers" ref={lineNumbersRef}>
            {lineNumbers.map((num) => (
              <span key={num} className="line-number-item">
                {num}
              </span>
            ))}
          </div>

          {/* Text Area */}
          <textarea
            ref={textareaRef}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onScroll={handleScroll}
            onKeyDown={handleKeyDown}
            placeholder={
              contextType === 'snippet'
                ? '# Paste code snippet here (e.g. Python, SQL, Shell)...\n# Press Cmd+Enter to run security audit'
                : 'Paste application stack trace or traceback here...\nTraceback (most recent call last):\n  File "app.py", line 42, in ...'
            }
            className="code-textarea"
            spellCheck="false"
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
          />
        </div>
      </div>

      {/* Editor Footer Bar */}
      <div className="editor-footer">
        <div className="editor-stats">
          <span>{lineCount} {lineCount === 1 ? 'line' : 'lines'}</span>
          <span className="stat-separator">•</span>
          <span>{code.length} chars</span>
          <span className="stat-separator">•</span>
          <span className="shortcut-hint">Press <kbd>⌘</kbd> + <kbd>↵</kbd></span>
        </div>

        <button
          type="button"
          onClick={onAnalyze}
          disabled={isLoading || !code.trim()}
          className="btn-primary run-audit-btn"
        >
          {isLoading ? (
            <>
              <div className="spinner" />
              <span>Scanning Signatures...</span>
            </>
          ) : (
            <>
              <Play size={14} fill="currentColor" />
              <span>Run Security Analysis</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
