import React from 'react';
import { Sparkles, ShieldAlert, CheckCircle2, Play } from 'lucide-react';
import type { SampleSnippet } from '../types';

interface DemoSamplesPageProps {
  samples: SampleSnippet[];
  onLoadAndRun: (sample: SampleSnippet) => void;
}

export const DemoSamplesPage: React.FC<DemoSamplesPageProps> = ({ samples, onLoadAndRun }) => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="max-w-3xl space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-400 text-xs font-semibold">
          <Sparkles className="h-3.5 w-3.5 text-amber-400" />
          <span>Curated Vulnerability Test Cases</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
          Realistic Code Samples & Safe Demo Mode
        </h2>
        <p className="text-sm text-slate-400 leading-relaxed">
          Test SentinelCode instantly without requiring external API keys. Each fixture demonstrates verified real-world anti-patterns, OWASP Top 10 vulnerabilities, or refactored clean code.
        </p>
      </div>

      {/* Grid of Samples */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {samples.map((sample) => (
          <div
            key={sample.id}
            className="flex flex-col justify-between p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl hover:border-slate-700 transition-all space-y-5"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider uppercase bg-slate-800 text-cyan-400 border border-slate-700">
                  {sample.language}
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  {sample.code.split('\n').length} lines
                </span>
              </div>

              <h3 className="text-lg font-bold text-slate-100">{sample.title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{sample.description}</p>

              {/* Target Vulnerabilities List */}
              <div className="space-y-1.5 pt-2">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                  {sample.expected_vulnerabilities.length > 0 ? 'Target Vulnerabilities:' : 'Key Characteristics:'}
                </span>
                {sample.expected_vulnerabilities.length > 0 ? (
                  <ul className="space-y-1">
                    {sample.expected_vulnerabilities.map((vuln, i) => (
                      <li key={i} className="flex items-center space-x-2 text-xs text-rose-300">
                        <ShieldAlert className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                        <span>{vuln}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="flex items-center space-x-2 text-xs text-emerald-300">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span>Parameterized SQL, constant-time compare, zero static defects.</span>
                  </div>
                )}
              </div>
            </div>

            {/* Action Button */}
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={() => onLoadAndRun(sample)}
                className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md shadow-blue-600/20 transition-all"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Load in Workspace & Audit</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
