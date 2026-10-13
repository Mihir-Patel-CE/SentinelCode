import React from 'react';
import { ShieldAlert, ShieldCheck, Cpu, Activity } from 'lucide-react';
import type { Review, Severity } from '../../types';

interface MetricsCardsProps {
  review: Review;
  selectedSeverity: Severity | 'all';
  setSelectedSeverity: (sev: Severity | 'all') => void;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({
  review,
  selectedSeverity,
  setSelectedSeverity,
}) => {
  const findings = review.findings;

  const countBySeverity = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  const staticCount = findings.filter((f) => f.source === 'static').length;
  const aiCount = findings.filter((f) => f.source === 'ai').length;

  // Color helper for scores
  const getScoreColor = (score: number | null) => {
    if (score === null) return 'text-slate-400 border-slate-700 bg-slate-900/40';
    if (score >= 90) return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
    if (score >= 70) return 'text-blue-400 border-blue-500/30 bg-blue-950/20';
    if (score >= 50) return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
    return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
  };

  const formatStatus = (status: string) => {
    switch (status) {
      case 'completed':
        return { label: 'Audit Completed', color: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60' };
      case 'completed_with_limitations':
        return { label: 'Completed with Limitations (Syntax/Parse issues)', color: 'bg-amber-950/60 text-amber-400 border-amber-800/60' };
      case 'unsupported_language':
        return { label: 'Unsupported Language (Advisory AI)', color: 'bg-indigo-950/60 text-indigo-400 border-indigo-800/60' };
      case 'invalid_input':
        return { label: 'Invalid Input', color: 'bg-rose-950/60 text-rose-400 border-rose-800/60' };
      case 'failed':
        return { label: 'Analysis Failed (Toolchain Error)', color: 'bg-rose-950/60 text-rose-400 border-rose-800/60' };
      default:
        return { label: status, color: 'bg-slate-800 text-slate-300 border-slate-700' };
    }
  };

  const statusInfo = formatStatus(review.status);

  return (
    <div className="space-y-4">
      {/* Status banner */}
      <div className="flex flex-wrap items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 gap-2 text-xs">
        <div className="flex items-center space-x-2">
          <span className="text-slate-400">Analysis State:</span>
          <span className={`px-2 py-0.5 rounded font-semibold text-[11px] border ${statusInfo.color}`}>
            {statusInfo.label}
          </span>
        </div>
        {review.coverage_summary && (
          <span className="text-slate-400 text-[11px]">
            {review.coverage_summary}
          </span>
        )}
      </div>

      {/* 3 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Security Score */}
        <div className={`p-4 rounded-xl border ${getScoreColor(review.security_score)} backdrop-blur-sm transition-all`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Security Score</span>
            {review.security_score !== null && review.security_score >= 80 ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-rose-400" />
            )}
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold tracking-tight">
              {review.security_score !== null ? review.security_score : 'N/A'}
            </span>
            {review.security_score !== null && <span className="text-xs text-slate-500">/ 100</span>}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {review.security_score === null
              ? 'Provisional score unavailable due to analysis status'
              : review.security_score >= 90
              ? 'Zero critical exploits detected in submitted code'
              : `${countBySeverity.critical + countBySeverity.high} severe risks require attention`}
          </p>
        </div>

        {/* Quality Score */}
        <div className={`p-4 rounded-xl border ${getScoreColor(review.quality_score)} backdrop-blur-sm transition-all`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Code Quality</span>
            <Activity className="h-4 w-4 text-blue-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold tracking-tight">
              {review.quality_score !== null ? review.quality_score : 'N/A'}
            </span>
            {review.quality_score !== null && <span className="text-xs text-slate-500">/ 100</span>}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Syntax, unhandled errors & structural compliance
          </p>
        </div>

        {/* Maintainability Index */}
        <div className={`p-4 rounded-xl border ${getScoreColor(review.maintainability_index)} backdrop-blur-sm transition-all`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Maintainability</span>
            <Cpu className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold tracking-tight">
              {review.maintainability_index !== null ? review.maintainability_index : 'N/A'}
            </span>
            {review.maintainability_index !== null && <span className="text-xs text-slate-500">/ 100</span>}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Defect density & cognitive complexity rating
          </p>
        </div>
      </div>

      {/* Severity Filter Badges */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-slate-900 border border-slate-800 rounded-xl text-xs">
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 font-medium">Filter Findings:</span>
          <button
            onClick={() => setSelectedSeverity('all')}
            className={`px-2.5 py-1 rounded-md font-semibold transition-colors ${
              selectedSeverity === 'all'
                ? 'bg-slate-700 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({findings.length})
          </button>
          <button
            onClick={() => setSelectedSeverity('critical')}
            className={`px-2.5 py-1 rounded-md font-semibold transition-colors ${
              selectedSeverity === 'critical'
                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                : 'text-rose-400/70 hover:text-rose-400'
            }`}
          >
            Critical ({countBySeverity.critical})
          </button>
          <button
            onClick={() => setSelectedSeverity('high')}
            className={`px-2.5 py-1 rounded-md font-semibold transition-colors ${
              selectedSeverity === 'high'
                ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                : 'text-orange-400/70 hover:text-orange-400'
            }`}
          >
            High ({countBySeverity.high})
          </button>
          <button
            onClick={() => setSelectedSeverity('medium')}
            className={`px-2.5 py-1 rounded-md font-semibold transition-colors ${
              selectedSeverity === 'medium'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                : 'text-amber-400/70 hover:text-amber-400'
            }`}
          >
            Medium ({countBySeverity.medium})
          </button>
          <button
            onClick={() => setSelectedSeverity('low')}
            className={`px-2.5 py-1 rounded-md font-semibold transition-colors ${
              selectedSeverity === 'low'
                ? 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                : 'text-blue-400/70 hover:text-blue-400'
            }`}
          >
            Low ({countBySeverity.low})
          </button>
        </div>

        {/* Source Distribution Tag */}
        <div className="flex items-center space-x-2 text-slate-500 text-[11px]">
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
            Static AST: {staticCount}
          </span>
          <span className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/40">
            Advisory AI: {aiCount}
          </span>
        </div>
      </div>
    </div>
  );
};
