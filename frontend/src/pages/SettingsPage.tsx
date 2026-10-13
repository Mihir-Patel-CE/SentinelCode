import React, { useState, useEffect } from 'react';
import { Settings, Shield, Sparkles, Check, Save, Key, AlertTriangle } from 'lucide-react';
import { UserSettings, Severity } from '../types';
import { api } from '../services/api';
import { useAuth } from '../context/useAuth';

export const SettingsPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [settings, setSettings] = useState<UserSettings>({
    enable_security_checks: true,
    enable_quality_checks: true,
    enable_performance_checks: true,
    enable_ai_analysis: true,
    preferred_ai_provider: 'mock',
    preferred_ai_model: 'sentinel-heuristic-v1',
    severity_threshold: 'info',
  });
  const [apiKey, setApiKey] = useState<string>('');
  const [saved, setSaved] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    const loadSettings = async () => {
      if (isAuthenticated) {
        try {
          const res = await api.getSettings();
          setSettings(res);
        } catch (err) {
          console.error('Failed to load settings:', err);
        }
      }
    };
    loadSettings();
  }, [isAuthenticated]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (isAuthenticated) {
        await api.updateSettings(settings);
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (err) {
      console.error('Save failed:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="space-y-2">
        <h2 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
          <Settings className="h-6 w-6 text-blue-400" />
          <span>Audit Engine & Provider Settings</span>
        </h2>
        <p className="text-xs text-slate-400">
          Configure rule categories, deterministic static analysis parameters, and AI model routing.
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Analysis Rules Toggles */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-lg space-y-4">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <span>Inspection Rulesets</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <label className="flex items-start space-x-3 p-3.5 bg-slate-950 border border-slate-800 rounded-xl cursor-pointer hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={settings.enable_security_checks}
                onChange={(e) =>
                  setSettings({ ...settings, enable_security_checks: e.target.checked })
                }
                className="mt-0.5 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0"
              />
              <div className="text-xs space-y-0.5">
                <span className="font-semibold text-slate-200 block">Security & Vulnerability Checks</span>
                <span className="text-slate-400 block">
                  Scans for SQLi, XSS, Command Injection, hardcoded secrets, and timing attacks.
                </span>
              </div>
            </label>

            <label className="flex items-start space-x-3 p-3.5 bg-slate-950 border border-slate-800 rounded-xl cursor-pointer hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={settings.enable_quality_checks}
                onChange={(e) =>
                  setSettings({ ...settings, enable_quality_checks: e.target.checked })
                }
                className="mt-0.5 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0"
              />
              <div className="text-xs space-y-0.5">
                <span className="font-semibold text-slate-200 block">Code Quality & Anti-Patterns</span>
                <span className="text-slate-400 block">
                  Checks for mutable defaults, loose equality coercion, and bare exceptions.
                </span>
              </div>
            </label>

            <label className="flex items-start space-x-3 p-3.5 bg-slate-950 border border-slate-800 rounded-xl cursor-pointer hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={settings.enable_performance_checks}
                onChange={(e) =>
                  setSettings({ ...settings, enable_performance_checks: e.target.checked })
                }
                className="mt-0.5 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0"
              />
              <div className="text-xs space-y-0.5">
                <span className="font-semibold text-slate-200 block">Performance & Resource Leaks</span>
                <span className="text-slate-400 block">
                  Identifies unclosed handles, blocking event loops, and inefficient loops.
                </span>
              </div>
            </label>

            <label className="flex items-start space-x-3 p-3.5 bg-slate-950 border border-slate-800 rounded-xl cursor-pointer hover:border-slate-700 transition-colors">
              <input
                type="checkbox"
                checked={settings.enable_ai_analysis}
                onChange={(e) =>
                  setSettings({ ...settings, enable_ai_analysis: e.target.checked })
                }
                className="mt-0.5 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0"
              />
              <div className="text-xs space-y-0.5">
                <span className="font-semibold text-slate-200 block">AI Reasoning & Remediation</span>
                <span className="text-slate-400 block">
                  Generates executive review summaries, architectural advice, and code diffs.
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* AI Provider & Routing */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-lg space-y-4">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Sparkles className="h-4 w-4 text-amber-400" />
            <span>AI Provider Integration</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Selected AI Engine
              </label>
              <select
                value={settings.preferred_ai_provider}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    preferred_ai_provider: e.target.value as any,
                  })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="mock">Offline Heuristic Engine (Zero-Config / Free)</option>
                <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
                <option value="gemini">Google Gemini (Gemini 1.5 Flash / Pro)</option>
                <option value="groq">Groq (Llama 3.3 70B Fast Inference)</option>
                <option value="ollama">Ollama (Local Self-Hosted LLM)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Severity Alert Threshold
              </label>
              <select
                value={settings.severity_threshold}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    severity_threshold: e.target.value as Severity,
                  })
                }
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="info">Informational (All findings)</option>
                <option value="low">Low Severity and above</option>
                <option value="medium">Medium Severity and above</option>
                <option value="high">High Severity and above</option>
                <option value="critical">Critical Severity only</option>
              </select>
            </div>
          </div>

          {settings.preferred_ai_provider !== 'mock' && (
            <div className="pt-2">
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center space-x-1.5">
                <Key className="h-3.5 w-3.5 text-amber-400" />
                <span>Custom Provider API Key (Optional Client Override)</span>
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-... or api key override"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                If omitted, the backend server environment variable will be utilized.
              </span>
            </div>
          )}

          <div className="p-3.5 bg-slate-950 border border-slate-800/80 rounded-xl text-xs text-slate-400 space-y-1">
            <div className="flex items-center space-x-1.5 text-amber-400 font-semibold text-[11px]">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>Provider-Agnostic Operation Notice</span>
            </div>
            <p>
              When using the default <strong>Offline Heuristic Engine</strong>, no external network requests or API keys are required.
              To route queries through OpenAI or Gemini in production, configure <code>OPENAI_API_KEY</code> or <code>GEMINI_API_KEY</code> in the server <code>.env</code> file.
            </p>
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center justify-end space-x-3">
          {saved && (
            <span className="flex items-center space-x-1.5 text-xs text-emerald-400 font-medium animate-in fade-in">
              <Check className="h-4 w-4" />
              <span>Settings saved successfully!</span>
            </span>
          )}
          <button
            type="submit"
            disabled={loading}
            className="flex items-center space-x-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/30 transition-all"
          >
            <Save className="h-3.5 w-3.5" />
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
};
