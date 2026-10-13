import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import React from 'react';
import { ReviewerPage } from '../pages/ReviewerPage';
import { CodeEditor } from '../components/editor/CodeEditor';
import { api } from '../services/api';
import type { Review, SupportedLanguage, SampleSnippet } from '../types';

const mockCSample: SampleSnippet = {
  id: 'c-buffer-overflow',
  title: 'C: Buffer Overflow',
  language: 'c',
  description: 'Unsafe strcpy sample',
  expected_vulnerabilities: ['Unbounded String Copy'],
  code: '#include <stdio.h>\n#include <string.h>\nvoid test(char *s) { char b[10]; strcpy(b, s); }\n',
};

const mockCppReview: Review = {
  id: 456,
  title: 'C++ Audit Review',
  language: 'cpp',
  code: '#include <iostream>',
  status: 'completed',
  security_score: 95,
  quality_score: 85,
  maintainability_index: 80,
  findings: [
    {
      id: 2,
      review_id: 456,
      rule_id: 'BUG-CPP-003',
      title: 'Dangling Reference to Local Stack Object',
      description: 'Returning reference to local stack variable',
      severity: 'high',
      category: 'bug',
      source: 'static',
      confidence: 'high',
      line_start: 5,
      suggested_fix: 'Return by value instead.',
    },
  ],
  created_at: new Date().toISOString(),
};

describe('C and C++ Frontend Language Support & Routing Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders separate C and C++ options in language selector', () => {
    let currentLang: SupportedLanguage = 'auto';
    const setLang = (l: SupportedLanguage) => {
      currentLang = l;
    };

    render(
      <CodeEditor
        code="// test"
        setCode={() => {}}
        language={currentLang}
        setLanguage={setLang}
        title="Test"
        setTitle={() => {}}
        enableAi={false}
        setEnableAi={() => {}}
        isAnalyzing={false}
        onAnalyze={() => {}}
        samples={[]}
        onSelectSample={() => {}}
      />
    );

    const select = screen.getByRole('combobox');
    expect(select).toBeInTheDocument();

    const optionC = screen.getByRole('option', { name: 'C' });
    const optionCpp = screen.getByRole('option', { name: 'C++' });

    expect(optionC).toBeInTheDocument();
    expect(optionC).toHaveValue('c');

    expect(optionCpp).toBeInTheDocument();
    expect(optionCpp).toHaveValue('cpp');
  });

  it('routes C selection and triggers analyzeCode with language="c"', async () => {
    const analyzeSpy = vi.spyOn(api, 'analyzeCode').mockResolvedValue(mockCppReview);

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('#include <stdio.h>\nvoid test() {}');
      const [language, setLanguage] = React.useState<SupportedLanguage>('c');
      const [title, setTitle] = React.useState('C Audit');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={setReview}
          samples={[mockCSample]}
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

    const runBtn = screen.getByRole('button', { name: /run audit/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(analyzeSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          language: 'c',
          code: expect.stringContaining('#include <stdio.h>'),
        })
      );
    });
  });

  it('routes C++ selection and triggers analyzeCode with language="cpp"', async () => {
    const analyzeSpy = vi.spyOn(api, 'analyzeCode').mockResolvedValue(mockCppReview);

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('#include <iostream>\nint main() {}');
      const [language, setLanguage] = React.useState<SupportedLanguage>('cpp');
      const [title, setTitle] = React.useState('C++ Audit');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={setReview}
          samples={[]}
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

    const runBtn = screen.getByRole('button', { name: /run audit/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(analyzeSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          language: 'cpp',
          code: expect.stringContaining('#include <iostream>'),
        })
      );
    });
  });

  it('renders visible language ribbon and switches language on button click', async () => {
    const analyzeSpy = vi.spyOn(api, 'analyzeCode').mockResolvedValue(mockCppReview);

    const Harness = () => {
      const [review, setReview] = React.useState<Review | null>(null);
      const [code, setCode] = React.useState('public class Test {}');
      const [language, setLanguage] = React.useState<SupportedLanguage>('auto');
      const [title, setTitle] = React.useState('Java Audit');

      return (
        <ReviewerPage
          currentReview={review}
          setCurrentReview={setReview}
          samples={[]}
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

    // Verify Target Language label and quick-select buttons exist
    expect(screen.getByText(/Target Language:/i)).toBeInTheDocument();

    const javaButton = screen.getByTitle('Select Java (Static & Security)');
    expect(javaButton).toBeInTheDocument();

    // Click Java button
    fireEvent.click(javaButton);

    const runBtn = screen.getByRole('button', { name: /run audit/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(analyzeSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          language: 'java',
          code: expect.stringContaining('public class Test'),
        })
      );
    });
  });
});
