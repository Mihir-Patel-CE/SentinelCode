import React, { useRef } from 'react';
import { Play, Sparkles, Copy, Trash2, Check, FileCode, Code2 } from 'lucide-react';
import type { SupportedLanguage, SampleSnippet } from '../../types';

export const LANGUAGE_OPTIONS: { id: SupportedLanguage; label: string; analyzer: string; badge: string }[] = [
  { id: 'auto', label: 'Auto Detect', analyzer: 'Smart Routing', badge: 'Auto' },
  { id: 'c', label: 'C', analyzer: 'Clang / C17', badge: 'Clang' },
  { id: 'cpp', label: 'C++', analyzer: 'Clang++ / RAII', badge: 'Clang++' },
  { id: 'python', label: 'Python', analyzer: 'AST & Security', badge: 'AST' },
  { id: 'java', label: 'Java', analyzer: 'Static & Security', badge: 'Static' },
  { id: 'javascript', label: 'JavaScript', analyzer: 'JS Syntax & Security', badge: 'JS' },
  { id: 'typescript', label: 'TypeScript', analyzer: 'TS Type & Suppression', badge: 'TS' },
  { id: 'go', label: 'Go', analyzer: 'Advisory AI', badge: 'AI' },
  { id: 'rust', label: 'Rust', analyzer: 'Advisory AI', badge: 'AI' },
];

interface CodeEditorProps {
  code: string;
  setCode: (code: string) => void;
  language: SupportedLanguage;
  setLanguage: (lang: SupportedLanguage) => void;
  title: string;
  setTitle: (title: string) => void;
  enableAi: boolean;
  setEnableAi: (enable: boolean) => void;
  isAnalyzing: boolean;
  onAnalyze: () => void;
  samples: SampleSnippet[];
  onSelectSample: (sample: SampleSnippet) => void;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  setCode,
  language,
  setLanguage,
  title,
  setTitle,
  enableAi,
  setEnableAi,
  isAnalyzing,
  onAnalyze,
  samples,
  onSelectSample,
}) => {
  const [copied, setCopied] = React.useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const lines = code.split('\n');
  const lineCount = lines.length;

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Tab key indentation support
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = e.currentTarget.selectionStart;
      const end = e.currentTarget.selectionEnd;
      const newCode = code.substring(0, start) + '    ' + code.substring(end);
      setCode(newCode);
      setTimeout(() => {
        if (textareaRef.current) {
          textareaRef.current.selectionStart = textareaRef.current.selectionEnd = start + 4;
        }
      }, 0);
    }
    // Cmd/Ctrl + Enter shortcut to run audit
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!isAnalyzing && code.trim()) {
        onAnalyze();
      }
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Editor Top Bar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-3 bg-slate-950 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-3 flex-1 min-w-[200px]">
          <FileCode className="h-4 w-4 text-blue-400 shrink-0" />
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Review Title (e.g. Auth Service Audit)"
            className="bg-transparent border-0 text-sm font-medium text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500/50 rounded px-1.5 py-0.5 w-full max-w-sm"
          />
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center space-x-2 shrink-0">
          {/* Sample Snippet Selector */}
          {samples.length > 0 && (
            <select
              onChange={(e) => {
                const selected = samples.find((s) => s.id === e.target.value);
                if (selected) onSelectSample(selected);
              }}
              defaultValue=""
              className="bg-slate-900 border border-slate-700 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
            >
              <option value="" disabled>Load Sample Bug...</option>
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title}
                </option>
              ))}
            </select>
          )}

          {/* Language Selector Dropdown */}
          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1">
            <span className="text-[11px] font-medium text-slate-400 flex items-center gap-1 select-none">
              <Code2 className="h-3.5 w-3.5 text-blue-400 shrink-0" />
              <span>Language:</span>
            </span>
            <select
              id="language-selector"
              aria-label="Programming Language"
              value={language}
              onChange={(e) => setLanguage(e.target.value as SupportedLanguage)}
              className="bg-slate-950 border border-slate-700 text-xs font-semibold text-cyan-400 rounded px-2 py-0.5 focus:outline-none focus:border-blue-500 uppercase tracking-wider cursor-pointer"
            >
              <option value="auto" className="bg-slate-900 text-slate-100">Auto Detect</option>
              <option value="c" className="bg-slate-900 text-slate-100">C</option>
              <option value="cpp" className="bg-slate-900 text-slate-100">C++</option>
              <option value="python" className="bg-slate-900 text-slate-100">Python</option>
              <option value="java" className="bg-slate-900 text-slate-100">Java</option>
              <option value="javascript" className="bg-slate-900 text-slate-100">JavaScript</option>
              <option value="typescript" className="bg-slate-900 text-slate-100">TypeScript</option>
              <option value="go" className="bg-slate-900 text-slate-100">Go</option>
              <option value="rust" className="bg-slate-900 text-slate-100">Rust</option>
            </select>
          </div>

          {/* Copy Button */}
          <button
            type="button"
            onClick={handleCopy}
            title="Copy code"
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
          >
            {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
          </button>

          {/* Clear Button */}
          <button
            type="button"
            onClick={() => setCode('')}
            title="Clear editor"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-md transition-colors"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Visible Quick Language Ribbon */}
      <div className="flex items-center px-4 py-2 bg-slate-950/90 border-b border-slate-800 gap-1.5 overflow-x-auto scrollbar-none text-xs">
        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider shrink-0 mr-1 flex items-center gap-1">
          Target Language:
        </span>
        {LANGUAGE_OPTIONS.map((item) => {
          const isSelected = language === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setLanguage(item.id)}
              className={`px-2.5 py-1 rounded-md font-mono text-[11px] font-semibold shrink-0 transition-all flex items-center gap-1.5 ${
                isSelected
                  ? 'bg-blue-600/25 text-cyan-300 border border-cyan-500/60 shadow-sm shadow-cyan-500/10'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
              title={`Select ${item.label} (${item.analyzer})`}
            >
              <span>{item.label}</span>
              <span
                className={`text-[9px] px-1 py-0.5 rounded font-sans uppercase font-normal ${
                  isSelected
                    ? 'bg-cyan-500/20 text-cyan-200'
                    : 'bg-slate-800 text-slate-500'
                }`}
              >
                {item.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* Editor Body with Line Numbers */}
      <div className="relative flex-1 flex overflow-hidden font-mono text-xs sm:text-sm bg-slate-950">
        {/* Line Gutter */}
        <div className="select-none py-3 px-3 text-right bg-slate-900/60 text-slate-600 border-r border-slate-800/80 font-mono text-xs leading-6 min-w-[3rem]">
          {Array.from({ length: Math.max(1, lineCount) }).map((_, i) => (
            <div key={i}>{i + 1}</div>
          ))}
        </div>

        {/* Text Area */}
        <textarea
          ref={textareaRef}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Paste or type code here for static security analysis and AI audit..."
          spellCheck={false}
          className="flex-1 p-3 bg-transparent text-slate-200 resize-none focus:outline-none leading-6 font-mono whitespace-pre overflow-auto code-editor-textarea"
        />
      </div>

      {/* Editor Footer / Audit Trigger */}
      <div className="flex flex-wrap items-center justify-between px-4 py-3 bg-slate-950 border-t border-slate-800 gap-3">
        {/* AI Toggle & Metadata */}
        <div className="flex items-center space-x-4 text-xs text-slate-400">
          <label className="flex items-center space-x-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={enableAi}
              onChange={(e) => setEnableAi(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0"
            />
            <span className="flex items-center space-x-1 text-slate-300">
              <Sparkles className="h-3.5 w-3.5 text-amber-400" />
              <span>AI Remediation & Diffs</span>
            </span>
          </label>
          <span className="text-slate-600">|</span>
          <span>{lineCount} lines • {code.length} chars</span>
        </div>

        {/* Run Audit Button */}
        <button
          type="button"
          onClick={onAnalyze}
          disabled={isAnalyzing || !code.trim()}
          className="flex items-center space-x-2 px-5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold shadow-lg shadow-blue-600/25 transition-all"
        >
          {isAnalyzing ? (
            <>
              <div className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Auditing AST & AI...</span>
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Run Audit</span>
              <kbd className="hidden sm:inline-block ml-1 px-1.5 py-0.5 text-[10px] bg-blue-800/60 rounded text-blue-200 border border-blue-400/30">
                ⌘↵
              </kbd>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
