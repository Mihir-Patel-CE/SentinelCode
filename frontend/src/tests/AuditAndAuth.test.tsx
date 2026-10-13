import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import React from 'react';
import { ReviewerPage } from '../pages/ReviewerPage';
import { AuthModal } from '../components/auth/AuthModal';
import { AuthProvider } from '../context/AuthContext';
import { api } from '../services/api';
import type { Review, SampleSnippet } from '../types';

const mockSamples: SampleSnippet[] = [
  {
    id: 'sample-python-sql',
    title: 'Python SQL Injection Sample',
    language: 'python',
    description: 'SQL Injection demonstration',
    expected_vulnerabilities: ['SQL Injection'],
    code: 'import sqlite3\ndef query(user):\n    return sqlite3.connect("db").cursor().execute(f"SELECT * FROM users WHERE name=\'{user}\'")\n',
  },
];

const mockReviewSuccess: Review = {
  id: 123,
  title: 'Test Audit',
  language: 'python',
  code: 'import sqlite3',
  status: 'completed',
  security_score: 45,
  quality_score: 60,
  maintainability_index: 70,
  findings: [
    {
      id: 1,
      review_id: 123,
      title: 'SQL Injection via String Formatting',
      description: 'Dynamic user query passed directly into cursor.execute()',
      severity: 'critical',
      category: 'security',
      source: 'static',
      confidence: 'high',
      line_start: 3,
      suggested_fix: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE name=?", (user,))',
    },
  ],
  created_at: new Date().toISOString(),
};

describe('Code Audit Regression Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('runs audit successfully and renders findings while resetting loading state', async () => {
    const analyzeSpy = vi.spyOn(api, 'analyzeCode').mockResolvedValue(mockReviewSuccess);

    let currentReviewState: Review | null = null;
    const setCurrentReview = (rev: Review | null) => {
      currentReviewState = rev;
    };

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('import sqlite3');
      const [language, setLanguage] = React.useState<any>('python');
      const [title, setTitle] = React.useState('Test Audit');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={(r) => {
            setReview(r);
            setCurrentReview(r);
          }}
          samples={mockSamples}
          code={code}
          setCode={setCode}
          language={language}
          setLanguage={setLanguage}
          title={title}
          setTitle={setTitle}
        />
      );
    };

    render(<Harness />);

    const runButton = screen.getByRole('button', { name: /run audit/i });
    expect(runButton).toBeInTheDocument();
    expect(runButton).not.toBeDisabled();

    fireEvent.click(runButton);

    // Verify analyzeCode was called once
    expect(analyzeSpy).toHaveBeenCalledTimes(1);
    expect(analyzeSpy).toHaveBeenCalledWith({
      title: 'Test Audit',
      language: 'python',
      code: 'import sqlite3',
      enable_ai: true,
    });

    // Wait for findings to render
    await waitFor(() => {
      expect(screen.getByText('SQL Injection via String Formatting')).toBeInTheDocument();
    });

    // Verify button loading state returned to normal
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /run audit/i })).toBeInTheDocument();
      expect(screen.queryByText(/auditing ast & ai/i)).not.toBeInTheDocument();
    });

    expect(currentReviewState).toEqual(mockReviewSuccess);
  });

  it('handles audit failure by displaying useful error message and clearing loading state', async () => {
    vi.spyOn(api, 'analyzeCode').mockRejectedValue(new Error('Audit timed out after 30 seconds'));

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('def broken(): pass');
      const [language, setLanguage] = React.useState<any>('python');
      const [title, setTitle] = React.useState('Timeout Test');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={setReview}
          samples={mockSamples}
          code={code}
          setCode={setCode}
          language={language}
          setLanguage={setLanguage}
          title={title}
          setTitle={setTitle}
        />
      );
    };

    render(<Harness />);

    const runButton = screen.getByRole('button', { name: /run audit/i });
    fireEvent.click(runButton);

    // Verify error banner is displayed
    await waitFor(() => {
      expect(screen.getByText('Audit timed out after 30 seconds')).toBeInTheDocument();
    });

    // Verify loading indicator is cleared and button is active again
    expect(screen.getByRole('button', { name: /run audit/i })).toBeInTheDocument();
    expect(screen.queryByText(/auditing ast & ai/i)).not.toBeInTheDocument();
  });

  it('prevents duplicate concurrent audit requests when clicked multiple times', async () => {
    let resolveAnalysis: (val: Review) => void = () => {};
    const pendingPromise = new Promise<Review>((resolve) => {
      resolveAnalysis = resolve;
    });

    const analyzeSpy = vi.spyOn(api, 'analyzeCode').mockReturnValue(pendingPromise);

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('def check(): pass');
      const [language, setLanguage] = React.useState<any>('python');
      const [title, setTitle] = React.useState('Concurrency Test');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={setReview}
          samples={mockSamples}
          code={code}
          setCode={setCode}
          language={language}
          setLanguage={setLanguage}
          title={title}
          setTitle={setTitle}
        />
      );
    };

    render(<Harness />);

    const runButton = screen.getByRole('button', { name: /run audit/i });
    fireEvent.click(runButton);

    // Fast second and third click while in-flight
    fireEvent.click(runButton);
    fireEvent.click(runButton);

    // Should only have been called once
    expect(analyzeSpy).toHaveBeenCalledTimes(1);

    // Now resolve promise and check cleanup
    resolveAnalysis(mockReviewSuccess);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /run audit/i })).toBeInTheDocument();
    });
  });
});

describe('Demo Login Regression Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('executes demo login successfully, sets auth token, and closes modal', async () => {
    const requestSpy = vi.spyOn(api as any, 'request').mockImplementation(async (...args: any[]) => {
      const endpoint = args[0];
      if (endpoint === '/auth/demo-login') {
        return {
          access_token: 'mock-demo-jwt-token',
          token_type: 'bearer',
          expires_in: 86400,
        };
      }
      if (endpoint === '/auth/me') {
        return {
          id: 999,
          email: 'demouser@sentinelcode.dev',
          username: 'demodev',
          is_active: true,
          created_at: new Date().toISOString(),
        };
      }
      return {};
    });

    const handleClose = vi.fn();

    render(
      <AuthProvider>
        <AuthModal isOpen={true} onClose={handleClose} />
      </AuthProvider>
    );

    const demoButton = screen.getByRole('button', { name: /quick 1-click demo login/i });
    expect(demoButton).toBeInTheDocument();

    fireEvent.click(demoButton);

    await waitFor(() => {
      expect(handleClose).toHaveBeenCalledTimes(1);
    });

    expect(requestSpy).toHaveBeenCalledWith('/auth/demo-login', expect.objectContaining({ method: 'POST' }));
    expect(localStorage.getItem('sentinel_token')).toBe('mock-demo-jwt-token');
  });

  it('displays clear error on demo login failure and resets loading state', async () => {
    vi.spyOn(api, 'demoLogin').mockRejectedValue(new Error('Demo login service unavailable'));

    const handleClose = vi.fn();

    render(
      <AuthProvider>
        <AuthModal isOpen={true} onClose={handleClose} />
      </AuthProvider>
    );

    const demoButton = screen.getByRole('button', { name: /quick 1-click demo login/i });
    fireEvent.click(demoButton);

    await waitFor(() => {
      expect(screen.getByText('Demo login service unavailable')).toBeInTheDocument();
    });

    expect(handleClose).not.toHaveBeenCalled();

    // Verify loading indicator reset and button re-enabled
    const restoredButton = screen.getByRole('button', { name: /quick 1-click demo login/i });
    expect(restoredButton).toBeInTheDocument();
    expect(restoredButton).not.toBeDisabled();
    expect(screen.queryByText(/authenticating demo/i)).not.toBeInTheDocument();
  });
});
