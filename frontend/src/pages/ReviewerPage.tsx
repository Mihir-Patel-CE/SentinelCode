import React, { useState } from 'react';
import { Download, AlertCircle, CheckCircle2, Terminal, ArrowRight } from 'lucide-react';
import { CodeEditor } from '../components/editor/CodeEditor';
import { MetricsCards } from '../components/review/MetricsCards';
import { FindingCard } from '../components/review/FindingCard';
import type { Review, SupportedLanguage, SampleSnippet, Severity } from '../types';
import { api } from '../services/api';

interface ReviewerPageProps {
  currentReview: Review | null;
  setCurrentReview: (review: Review | null) => void;
  samples: SampleSnippet[];
  code: string;
  setCode: (code: string) => void;
  language: SupportedLanguage;
  setLanguage: (lang: SupportedLanguage) => void;
  title: string;
  setTitle: (title: string) => void;
}

export const ReviewerPage: React.FC<ReviewerPageProps> = ({
  currentReview,
  setCurrentReview,
  samples,
  code,
  setCode,
  language,
  setLanguage,
  title,
  setTitle,
}) => {
  const [enableAi, setEnableAi] = useState<boolean>(true);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'all'>('all');

  const handleAnalyze = async () => {
    if (!code.trim() || isAnalyzing) return;
    setIsAnalyzing(true);
    setError(null);

    try {
      const review = await api.analyzeCode({
        title: title || `${language.toUpperCase()} Code Review`,
        language,
        code,
        enable_ai: enableAi,
      });
      setCurrentReview(review);
    } catch (err: any) {
      setError(err.message || 'Audit execution failed. Please check server availability.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSelectSample = (sample: SampleSnippet) => {
    if (isAnalyzing) return;
    setCode(sample.code);
    setLanguage(sample.language);
    setTitle(sample.title);
    setError(null);
  };

  const filteredFindings = currentReview
    ? currentReview.findings.filter((f) => {
        if (selectedSeverity === 'all') return true;
        return f.severity === selectedSeverity;
      })
    : [];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Error banner */}
      {error && (
        <div className="flex items-center space-x-2 p-3 bg-rose-950/40 border border-rose-800/60 rounded-xl text-xs text-rose-300">
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[640px]">
        {/* Left Side: Interactive Code Editor */}
        <div className="flex flex-col h-full">
          <CodeEditor
            code={code}
            setCode={setCode}
            language={language}
            setLanguage={setLanguage}
            title={title}
            setTitle={setTitle}
            enableAi={enableAi}
            setEnableAi={setEnableAi}
            isAnalyzing={isAnalyzing}
            onAnalyze={handleAnalyze}
            samples={samples}
            onSelectSample={handleSelectSample}
          />
        </div>

        {/* Right Side: Analysis Findings Panel */}
        <div className="flex flex-col h-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl p-4 sm:p-5">
          {currentReview ? (
            <div className="flex flex-col h-full space-y-4 overflow-y-auto pr-1">
              {/* Header with Title and Export Button */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <h3 className="text-base font-bold text-slate-100">{currentReview.title}</h3>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-800 text-cyan-400 border border-slate-700">
                      {currentReview.language}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Audited {new Date(currentReview.created_at).toLocaleTimeString()}
                  </p>
                </div>
                <a
                  href={api.getExportUrl(currentReview.id)}
                  download
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
                >
                  <Download className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Export Report</span>
                </a>
              </div>

              {/* Metrics Overview Cards */}
              <MetricsCards
                review={currentReview}
                selectedSeverity={selectedSeverity}
                setSelectedSeverity={setSelectedSeverity}
              />

              {/* Executive Summary Narrative */}
              {currentReview.summary && (
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 text-xs text-slate-300 leading-relaxed">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                    Executive Review Summary
                  </div>
                  <p>{currentReview.summary}</p>
                </div>
              )}

              {/* Findings List */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between text-xs text-slate-400 font-semibold px-1">
                  <span>
                    Findings ({filteredFindings.length}{' '}
                    {selectedSeverity !== 'all' ? `filtered by ${selectedSeverity}` : ''})
                  </span>
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center bg-slate-950 border border-slate-800/60 rounded-xl space-y-2">
                    <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
                    <h4 className="text-sm font-semibold text-slate-200">No Findings for Selected Filter</h4>
                    <p className="text-xs text-slate-500">
                      {selectedSeverity === 'all'
                        ? 'No bugs, security issues, or code smells detected!'
                        : `No ${selectedSeverity} severity issues were found in this code.`}
                    </p>
                  </div>
                ) : (
                  filteredFindings.map((finding) => (
                    <FindingCard key={finding.id} finding={finding} />
                  ))
                )}
              </div>
            </div>
          ) : (
            /* Empty State: Guidance & Quick Load */
            <div className="flex flex-col items-center justify-center h-full text-center p-8 space-y-5">
              <div className="h-16 w-16 rounded-2xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shadow-inner">
                <Terminal className="h-8 w-8 text-cyan-400" />
              </div>
              <div className="max-w-md space-y-2">
                <h3 className="text-lg font-bold text-white">Ready for Code Audit</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Submit any C, C++, Python, JavaScript, TypeScript, or Java snippet to execute compiler diagnostics, deterministic static rules, and multi-provider AI reasoning.
                </p>
              </div>

              {/* Sample Quick Links */}
              {samples.length > 0 && (
                <div className="w-full max-w-sm space-y-2 pt-2">
                  <p className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">
                    Try a pre-loaded sample bug:
                  </p>
                  <div className="grid grid-cols-1 gap-2">
                    {samples.slice(0, 3).map((sample) => (
                      <button
                        key={sample.id}
                        onClick={() => handleSelectSample(sample)}
                        className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-blue-500/50 hover:bg-slate-800/40 text-left transition-all text-xs"
                      >
                        <div className="truncate pr-2">
                          <span className="font-medium text-slate-200 block truncate">{sample.title}</span>
                          <span className="text-[10px] text-slate-500 uppercase">{sample.language}</span>
                        </div>
                        <ArrowRight className="h-3.5 w-3.5 text-slate-500 shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
