import React, { useState, useEffect } from 'react';
import { X, CheckCircle2, AlertTriangle, Layers, Info } from 'lucide-react';
import { LanguageCapability } from '../../types';
import { api } from '../../services/api';

interface LanguageMatrixModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LanguageMatrixModal: React.FC<LanguageMatrixModalProps> = ({ isOpen, onClose }) => {
  const [capabilities, setCapabilities] = useState<LanguageCapability[]>([]);
  const [hasLoaded, setHasLoaded] = useState<boolean>(false);

  useEffect(() => {
    let ignore = false;
    if (isOpen && !hasLoaded) {
      api.getLanguages()
        .then((data) => {
          if (!ignore) {
            setCapabilities(data);
            setHasLoaded(true);
          }
        })
        .catch((err) => {
          if (!ignore) {
            console.error('Failed to load language matrix:', err);
            setHasLoaded(true);
          }
        });
    }
    return () => {
      ignore = true;
    };
  }, [isOpen, hasLoaded]);

  const loading = isOpen && !hasLoaded;

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 sm:p-8 space-y-6 max-h-[90vh] overflow-y-auto">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Header */}
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400">
            <Layers className="h-5 w-5" />
            <span className="text-xs font-semibold uppercase tracking-wider">Multi-Language Architecture</span>
          </div>
          <h3 className="text-xl font-bold tracking-tight text-white">
            Supported Languages & Analyzer Coverage Matrix
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            SentinelCode runs deterministic language-specific static AST rules, scope resolution, and syntax balance checks, supplemented by advisory AI reasoning.
          </p>
        </div>

        {/* Content Table / Cards */}
        <div className="space-y-4">
          {loading ? (
            <div className="py-12 text-center text-xs text-slate-500">
              Loading language capability registry...
            </div>
          ) : (
            capabilities.map((lang) => (
              <div
                key={lang.id}
                className="p-4 bg-slate-950 border border-slate-800/80 rounded-xl space-y-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-sm text-slate-200">{lang.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 uppercase">
                      {lang.id}
                    </span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                      lang.status === 'supported'
                        ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                        : 'bg-amber-950/40 text-amber-400 border-amber-800/40'
                    }`}
                  >
                    {lang.status}
                  </span>
                </div>

                {/* Features list */}
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                    Analysis Capabilities:
                  </span>
                  <div className="flex flex-wrap gap-1.5 pt-0.5">
                    {lang.features.map((feat, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-slate-300"
                      >
                        <CheckCircle2 className="h-3 w-3 text-cyan-400 shrink-0" />
                        <span>{feat}</span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Limitations */}
                <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/60 text-[11px] text-slate-400 flex items-start space-x-2">
                  <Info className="h-3.5 w-3.5 text-slate-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-300">Analyzer Coverage Boundary: </span>
                    <span>{lang.limitations}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer Note */}
        <div className="p-3 bg-slate-950 border border-slate-800/60 rounded-xl text-xs text-slate-400 flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
          <span>
            Static analysis identifies verifiable defects and security anti-patterns. A 100/100 score does not guarantee zero runtime vulnerabilities in complex systems.
          </span>
        </div>
      </div>
    </div>
  );
};
