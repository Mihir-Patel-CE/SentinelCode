export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'bug' | 'quality' | 'performance' | 'style' | 'syntax';
export type FindingSource = 'static' | 'ai';
export type SupportedLanguage = 'auto' | 'c' | 'cpp' | 'python' | 'javascript' | 'typescript' | 'java' | 'go' | 'rust';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type AnalysisStatus = 'completed' | 'completed_with_limitations' | 'invalid_input' | 'unsupported_language' | 'failed';

export interface Finding {
  id: number;
  review_id: number;
  rule_id?: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  source: FindingSource;
  line_start?: number;
  line_end?: number;
  column_start?: number;
  column_end?: number;
  evidence?: string;
  confidence: ConfidenceLevel;
  suggested_fix?: string;
  fix_diff?: string;
}

export interface Review {
  id: number;
  user_id?: number;
  title: string;
  language: string;
  code: string;
  quality_score: number | null;
  security_score: number | null;
  maintainability_index: number | null;
  summary?: string;
  status: AnalysisStatus | string;
  coverage_summary?: string;
  created_at: string;
  findings: Finding[];
}

export interface ReviewListItem {
  id: number;
  title: string;
  language: string;
  status: string;
  quality_score: number | null;
  security_score: number | null;
  total_findings: number;
  created_at: string;
}

export interface ReviewListResponse {
  items: ReviewListItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface User {
  id: number;
  email: string;
  username: string;
  is_active: boolean;
  created_at: string;
}

export interface SampleSnippet {
  id: string;
  title: string;
  language: SupportedLanguage;
  description: string;
  expected_vulnerabilities: string[];
  code: string;
}

export interface UserSettings {
  enable_security_checks: boolean;
  enable_quality_checks: boolean;
  enable_performance_checks: boolean;
  enable_ai_analysis: boolean;
  preferred_ai_provider: string;
  preferred_ai_model: string;
  severity_threshold: Severity;
}

export interface LanguageCapability {
  id: string;
  name: string;
  status: 'supported' | 'experimental' | 'planned';
  features: string[];
  limitations: string;
}
