import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Info, Sparkles, ChevronDown, ChevronUp, Copy, Check, Wrench, Terminal } from 'lucide-react';
import { Finding, Severity } from '../../types';
import { DiffViewer } from './DiffViewer';

interface FindingCardProps {
  finding: Finding;
  onNavigateToLine?: (line: number) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onNavigateToLine }) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'critical':
        return {
          bg: 'bg-rose-950/40 text-rose-400 border-rose-800/60',
          icon: <ShieldAlert className="h-3.5 w-3.5" />,
          label: 'CRITICAL',
        };
      case 'high':
        return {
          bg: 'bg-orange-950/40 text-orange-400 border-orange-800/60',
          icon: <AlertTriangle className="h-3.5 w-3.5" />,
          label: 'HIGH',
        };
      case 'medium':
        return {
          bg: 'bg-amber-950/40 text-amber-400 border-amber-800/60',
          icon: <AlertTriangle className="h-3.5 w-3.5" />,
          label: 'MEDIUM',
        };
      case 'low':
        return {
          bg: 'bg-blue-950/40 text-blue-400 border-blue-800/60',
          icon: <Info className="h-3.5 w-3.5" />,
          label: 'LOW',
        };
      default:
        return {
          bg: 'bg-slate-800 text-slate-300 border-slate-700',
          icon: <Info className="h-3.5 w-3.5" />,
          label: 'INFO',
        };
    }
  };

  const badge = getSeverityBadge(finding.severity);

  const handleCopyFix = () => {
    if (finding.fix_diff || finding.suggested_fix) {
      navigator.clipboard.writeText(finding.fix_diff || finding.suggested_fix || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-sm hover:border-slate-700 transition-all">
      {/* Header */}
      <div
        className="p-3.5 flex items-start justify-between cursor-pointer select-none"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex-1 space-y-1.5 pr-2">
          {/* Tag row */}
          <div className="flex flex-wrap items-center gap-1.5">
            {/* Severity Pill */}
            <span
              className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold tracking-wider border ${badge.bg}`}
            >
              {badge.icon}
              <span>{badge.label}</span>
            </span>

            {/* Source Pill: STATIC vs AI */}
            {finding.source === 'static' ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-cyan-400 border border-slate-700">
                STATIC AST
              </span>
            ) : (
              <span className="inline-flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-950/60 text-purple-300 border border-purple-800/50">
                <Sparkles className="h-2.5 w-2.5 text-amber-300" />
                <span>ADVISORY AI</span>
              </span>
            )}

            {/* Confidence */}
            <span className="text-[10px] font-medium text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
              {finding.confidence === 'high' ? 'High Confidence' : 'Medium Confidence'}
            </span>

            {/* Rule ID */}
            {finding.rule_id && (
              <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                {finding.rule_id}
              </span>
            )}

            {/* Line / Column Location */}
            {finding.line_start && (
              <span
                onClick={(e) => {
                  e.stopPropagation();
                  if (onNavigateToLine && finding.line_start) {
                    onNavigateToLine(finding.line_start);
                  }
                }}
                className="text-[10px] font-mono font-medium text-slate-300 hover:text-blue-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 transition-colors"
              >
                Line {finding.line_start}
                {finding.column_start ? `:${finding.column_start}` : ''}
              </span>
            )}

            {/* Category */}
            <span className="text-[10px] uppercase font-semibold text-slate-500">
              • {finding.category}
            </span>
          </div>

          {/* Finding Title */}
          <h4 className="text-sm font-semibold text-slate-200">{finding.title}</h4>
        </div>

        {/* Expand / Collapse Icon */}
        <button className="text-slate-500 hover:text-slate-300 p-1">
          {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="px-3.5 pb-3.5 pt-0 space-y-3 border-t border-slate-800/60 mt-1">
          {/* Explanation Description */}
          <p className="text-xs text-slate-300 leading-relaxed pt-2">
            {finding.description}
          </p>

          {/* Code Evidence Snippet */}
          {finding.evidence && (
            <div className="rounded-lg bg-slate-950 border border-slate-800/80 p-2 text-xs font-mono">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1 flex items-center space-x-1">
                <Terminal className="h-3 w-3 text-cyan-400" />
                <span>Code Evidence Flagged in Submitted Input:</span>
              </div>
              <div className="p-1.5 bg-slate-900/80 rounded border-l-2 border-amber-400/80 text-slate-200 overflow-x-auto whitespace-pre">
                {finding.evidence}
              </div>
            </div>
          )}

          {/* Remediation Guidance */}
          {finding.suggested_fix && (
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-1">
              <div className="flex items-center space-x-1.5 text-slate-400 font-semibold text-[11px]">
                <Wrench className="h-3 w-3 text-cyan-400" />
                <span>Recommended Fix:</span>
              </div>
              <p className="text-slate-300">{finding.suggested_fix}</p>
            </div>
          )}

          {/* Diff Viewer */}
          {finding.fix_diff && (
            <div className="space-y-1.5">
              <DiffViewer diffText={finding.fix_diff} />
              <div className="flex justify-end">
                <button
                  onClick={handleCopyFix}
                  className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-800"
                >
                  {copied ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" />
                      <span className="text-emerald-400">Diff Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>Copy Fix Diff</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
