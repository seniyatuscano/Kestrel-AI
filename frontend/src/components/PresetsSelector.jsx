import React from 'react';
import { Database, Terminal, ShieldAlert, Key, CheckCircle2, FileCode, Zap } from 'lucide-react';

const CATEGORY_ICONS = {
  'Database Security': Database,
  'Code Execution': ShieldAlert,
  'System Security': Terminal,
  'Credential Security': Key,
  'Secure Architecture': CheckCircle2,
  'Diagnostic Error': FileCode,
};

export default function PresetsSelector({ samples, onSelectSample, currentCode }) {
  if (!samples || samples.length === 0) return null;

  return (
    <div className="presets-wrapper">
      <div className="presets-label-bar">
        <div className="presets-title-tag">
          <Zap size={14} className="presets-zap-icon" />
          <span>Quick Presets:</span>
        </div>
        <div className="presets-scroll-track">
          {samples.map((sample) => {
            const Icon = CATEGORY_ICONS[sample.category] || FileCode;
            const isSelected = currentCode.trim() === sample.code.trim();
            const isClean = sample.category === 'Secure Architecture';

            return (
              <button
                key={sample.id}
                type="button"
                onClick={() => onSelectSample(sample)}
                className={`preset-chip ${isSelected ? 'preset-chip-active' : ''} ${isClean ? 'preset-chip-clean' : ''}`}
                title={sample.description}
              >
                <Icon size={13} className="preset-chip-icon" />
                <span className="preset-chip-name">{sample.title}</span>
                {isSelected && <span className="preset-active-dot" />}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
