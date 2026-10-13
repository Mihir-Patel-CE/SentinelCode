import React from 'react';
import { GitCompare } from 'lucide-react';

interface DiffViewerProps {
  diffText: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diffText }) => {
  const lines = diffText.split('\n');

  return (
    <div className="rounded-lg overflow-hidden border border-slate-800 bg-slate-950 font-mono text-xs">
      <div className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold text-[11px]">
        <GitCompare className="h-3.5 w-3.5 text-blue-400" />
        <span>Proposed Remediation Diff</span>
      </div>
      <div className="p-2 overflow-x-auto space-y-0.5">
        {lines.map((line, idx) => {
          let lineClass = 'text-slate-400';
          let bgClass = '';
          if (line.startsWith('+')) {
            lineClass = 'text-emerald-400 font-medium';
            bgClass = 'bg-emerald-950/30';
          } else if (line.startsWith('-')) {
            lineClass = 'text-rose-400 font-medium';
            bgClass = 'bg-rose-950/30';
          } else if (line.startsWith('//') || line.startsWith('#')) {
            lineClass = 'text-slate-500 italic';
          }

          return (
            <div key={idx} className={`px-2 py-0.5 rounded flex items-start space-x-2 ${bgClass}`}>
              <span className="select-none text-slate-600 w-4 shrink-0 text-right">
                {line.startsWith('+') ? '+' : line.startsWith('-') ? '-' : ' '}
              </span>
              <span className={`whitespace-pre ${lineClass}`}>{line.replace(/^[+-]\s?/, '')}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
