import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { FindingCard } from '../components/review/FindingCard';
import { Finding } from '../types';

describe('FindingCard Component', () => {
  const mockStaticFinding: Finding = {
    id: 1,
    review_id: 10,
    rule_id: 'SEC-PY-001',
    title: 'SQL Injection in Query Execution',
    description: 'Direct string interpolation into database query allows SQL Injection.',
    severity: 'critical',
    category: 'security',
    source: 'static',
    line_start: 14,
    line_end: 14,
    confidence: 'high',
    evidence: 'db.execute(f"SELECT * FROM users WHERE id = {uid}")',
    suggested_fix: 'Use parameterized queries instead of string formatting.',
    fix_diff: '- cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n+ cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
  };

  it('renders critical severity badge and rule ID correctly', () => {
    render(<FindingCard finding={mockStaticFinding} />);

    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('STATIC AST')).toBeInTheDocument();
    expect(screen.getByText('SEC-PY-001')).toBeInTheDocument();
    expect(screen.getByText('Line 14')).toBeInTheDocument();
    expect(screen.getByText('SQL Injection in Query Execution')).toBeInTheDocument();
  });

  it('displays remediation diff and explanation', () => {
    render(<FindingCard finding={mockStaticFinding} />);

    expect(screen.getByText(/Direct string interpolation into database query/)).toBeInTheDocument();
    expect(screen.getByText(/Proposed Remediation Diff/)).toBeInTheDocument();
    expect(screen.getByText(/Code Evidence Flagged in Submitted Input:/)).toBeInTheDocument();
    expect(screen.getAllByText(/SELECT \* FROM users WHERE id/).length).toBeGreaterThan(0);
  });
});
