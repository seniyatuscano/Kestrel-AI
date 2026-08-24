import React from 'react';
import { History, ShieldAlert, ShieldCheck, ChevronRight, Trash2 } from 'lucide-react';

export default function ScanHistory({ history, onSelectHistory, onClearHistory }) {
  if (!history || history.length === 0) return null;

  const getSeverityBadgeClass = (score) => {
    if (score >= 5) return 'badge-critical';
    if (score === 4) return 'badge-high';
    if (score === 3) return 'badge-medium';
    if (score === 2) return 'badge-low';
    return 'badge-secure';
  };

  return (
    <div className="glass-panel history-card">
      <div className="history-header">
        <div className="history-title-group">
          <History size={14} className="history-icon" />
          <h4>Audit Session History ({history.length})</h4>
        </div>
        <button
          type="button"
          onClick={onClearHistory}
          className="btn-icon"
          title="Clear scan history"
        >
          <Trash2 size={13} />
        </button>
      </div>

      <div className="history-list">
        {history.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelectHistory(item)}
            className="history-item-btn"
          >
            <div className="history-item-left">
              <span className={`badge ${getSeverityBadgeClass(item.response.severity_score)}`}>
                {item.response.is_vulnerable ? `${item.response.severity_score}/5 Threat` : 'Secure'}
              </span>
              <span className="history-title">{item.title}</span>
            </div>
            <div className="history-item-right">
              <span className="history-time">{item.timestamp}</span>
              <ChevronRight size={13} className="history-chevron" />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
