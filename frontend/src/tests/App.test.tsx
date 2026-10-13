import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import App from '../App';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([]),
        status: 200,
      })
    )
  );
});

describe('SentinelCode Main Application', () => {
  it('renders navbar brand, workspace buttons, and code editor', async () => {
    render(<App />);

    const brandElements = screen.getAllByText('SentinelCode');
    expect(brandElements.length).toBeGreaterThanOrEqual(1);
    expect(brandElements[0]).toBeInTheDocument();

    expect(screen.getByText('Audit Workspace')).toBeInTheDocument();
    expect(screen.getByText('Run Audit')).toBeInTheDocument();
    expect(screen.getByText('AI Remediation & Diffs')).toBeInTheDocument();
  });
});
