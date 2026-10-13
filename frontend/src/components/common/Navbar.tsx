import React from 'react';
import { ShieldCheck, Code2, History, Settings, LogIn, LogOut, User, Sparkles, Layers } from 'lucide-react';
import { useAuth } from '../../context/useAuth';

interface NavbarProps {
  activeTab: 'reviewer' | 'history' | 'samples' | 'settings';
  setActiveTab: (tab: 'reviewer' | 'history' | 'samples' | 'settings') => void;
  onOpenAuth: () => void;
  onOpenMatrix: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onOpenAuth, onOpenMatrix }) => {
  const { user, isAuthenticated, logout } = useAuth();

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('reviewer')}>
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldCheck className="h-6 w-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold tracking-tight text-white">SentinelCode</span>
              <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">AI Code Review & Automated Bug Detection</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 sm:space-x-2">
          <button
            onClick={() => setActiveTab('reviewer')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              activeTab === 'reviewer'
                ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-450 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Code2 className="h-4 w-4" />
            <span>Audit Workspace</span>
          </button>

          <button
            onClick={() => setActiveTab('samples')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              activeTab === 'samples'
                ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Sparkles className="h-4 w-4 text-amber-400" />
            <span className="hidden sm:inline">Demo Fixtures</span>
            <span className="sm:hidden">Demos</span>
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              activeTab === 'history'
                ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <History className="h-4 w-4" />
            <span>Audit Logs</span>
          </button>

          <button
            onClick={() => setActiveTab('settings')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              activeTab === 'settings'
                ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Settings className="h-4 w-4" />
            <span className="hidden sm:inline">Settings</span>
          </button>

          <button
            onClick={onOpenMatrix}
            title="Inspect supported languages, analyzer rules, and known limitations"
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-cyan-400/90 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-950/70 border border-cyan-800/40 transition-colors"
          >
            <Layers className="h-3.5 w-3.5" />
            <span className="hidden md:inline">Coverage Matrix</span>
          </button>
        </nav>

        {/* User Auth Profile */}
        <div className="flex items-center space-x-3">
          {isAuthenticated && user ? (
            <div className="flex items-center space-x-3">
              <div className="hidden md:flex items-center space-x-2 px-3 py-1 bg-slate-900 border border-slate-800 rounded-full text-xs text-slate-300">
                <User className="h-3.5 w-3.5 text-blue-400" />
                <span className="font-medium text-slate-200">{user.username}</span>
              </div>
              <button
                onClick={logout}
                title="Sign out"
                className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors border border-transparent hover:border-red-500/20"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md shadow-blue-600/25 transition-all"
            >
              <LogIn className="h-3.5 w-3.5" />
              <span>Sign In / Demo</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
