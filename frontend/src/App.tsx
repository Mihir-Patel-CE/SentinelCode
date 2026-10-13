import React, { useState, useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Navbar } from './components/common/Navbar';
import { ReviewerPage } from './pages/ReviewerPage';
import { DemoSamplesPage } from './pages/DemoSamplesPage';
import { ReviewHistoryTable } from './components/history/ReviewHistoryTable';
import { SettingsPage } from './pages/SettingsPage';
import { AuthModal } from './components/auth/AuthModal';
import { LanguageMatrixModal } from './components/common/LanguageMatrixModal';
import { Review, SupportedLanguage, SampleSnippet } from './types';
import { api } from './services/api';

const DEFAULT_PYTHON_CODE = `import sqlite3

def get_user_profile(db_connection, user_id):
    cursor = db_connection.cursor()
    # SECURITY RISK: Direct string interpolation into SQL query leads to SQL Injection
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
`;

export function AppContent() {
  const [activeTab, setActiveTab] = useState<'reviewer' | 'history' | 'samples' | 'settings'>('reviewer');
  const [isAuthOpen, setIsAuthOpen] = useState<boolean>(false);
  const [isMatrixOpen, setIsMatrixOpen] = useState<boolean>(false);
  const [samples, setSamples] = useState<SampleSnippet[]>([]);
  const [currentReview, setCurrentReview] = useState<Review | null>(null);

  // Editor persistent state
  const [code, setCode] = useState<string>(DEFAULT_PYTHON_CODE);
  const [language, setLanguage] = useState<SupportedLanguage>('auto');
  const [title, setTitle] = useState<string>('User Profile Query Audit');

  // Load sample snippets on start
  useEffect(() => {
    const fetchSamples = async () => {
      try {
        const data = await api.getSamples();
        setSamples(data);
      } catch (err) {
        console.error('Failed to load sample snippets:', err);
      }
    };
    fetchSamples();
  }, []);

  const handleLoadAndRun = async (sample: SampleSnippet) => {
    setCode(sample.code);
    setLanguage(sample.language);
    setTitle(sample.title);
    setActiveTab('reviewer');

    // Trigger analysis immediately
    try {
      const review = await api.analyzeCode({
        title: sample.title,
        language: sample.language,
        code: sample.code,
        enable_ai: true,
      });
      setCurrentReview(review);
    } catch (err) {
      console.error('Auto-audit failed:', err);
    }
  };

  const handleSelectReviewFromHistory = async (id: number) => {
    try {
      const review = await api.getReview(id);
      setCurrentReview(review);
      setCode(review.code);
      setLanguage(review.language as SupportedLanguage);
      setTitle(review.title);
      setActiveTab('reviewer');
    } catch (err) {
      console.error('Failed to load review details:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600/30 selection:text-white">
      {/* Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAuth={() => setIsAuthOpen(true)}
        onOpenMatrix={() => setIsMatrixOpen(true)}
      />

      {/* Main View Area */}
      <main className="flex-1 pb-12">
        {activeTab === 'reviewer' && (
          <ReviewerPage
            currentReview={currentReview}
            setCurrentReview={setCurrentReview}
            samples={samples}
            code={code}
            setCode={setCode}
            language={language}
            setLanguage={setLanguage}
            title={title}
            setTitle={setTitle}
          />
        )}

        {activeTab === 'samples' && (
          <DemoSamplesPage
            samples={samples}
            onLoadAndRun={handleLoadAndRun}
          />
        )}

        {activeTab === 'history' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
            <div className="space-y-1">
              <h2 className="text-2xl font-bold tracking-tight text-white">Security & Quality Audit History</h2>
              <p className="text-xs text-slate-400">
                Browse, search, export, or revisit prior code inspections.
              </p>
            </div>
            <ReviewHistoryTable onSelectReview={handleSelectReviewFromHistory} />
          </div>
        )}

        {activeTab === 'settings' && <SettingsPage />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-slate-400">SentinelCode</span>
            <span>—</span>
            <span>AI Code Review & Static Bug Detection Platform</span>
          </div>
          <div className="flex items-center space-x-4">
            <span>Deterministic AST Analysis</span>
            <span>•</span>
            <span>Multi-LLM Integration</span>
            <span>•</span>
            <span>Zero-Trust Sandboxing</span>
          </div>
        </div>
      </footer>

      {/* Authentication Dialog */}
      <AuthModal isOpen={isAuthOpen} onClose={() => setIsAuthOpen(false)} />

      {/* Language Capability & Limitations Matrix */}
      <LanguageMatrixModal isOpen={isMatrixOpen} onClose={() => setIsMatrixOpen(false)} />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
