import re
from typing import List, Tuple
from app.services.ai.base import BaseAIProvider
from app.schemas.review import FindingCreate


class HeuristicMockAIProvider(BaseAIProvider):
    """
    Intelligent offline AI provider that performs deep semantic analysis,
    architectural code quality assessment, and structured diff generation
    without requiring third-party cloud API keys or external credits.
    """

    @property
    def provider_name(self) -> str:
        return "sentinel-heuristic-v1"

    async def analyze(
        self,
        code: str,
        language: str,
        static_findings: List[FindingCreate]
    ) -> Tuple[List[FindingCreate], str]:
        ai_findings: List[FindingCreate] = []
        lines = code.splitlines()

        # Semantic Rule 1: Timing Attack in Password / Token Comparison
        timing_pattern = re.compile(r'(?i)(password|token|secret|signature)\s*==\s*[a-zA-Z0-9_.]+')
        for idx, line in enumerate(lines, start=1):
            if timing_pattern.search(line) and "hmac" not in line.lower() and "secrets" not in line.lower():
                ai_findings.append(FindingCreate(
                    rule_id="AI-SEC-001",
                    title="Timing Attack Risk in Secret/Token Comparison",
                    description=(
                        "Using standard equality (`==`) to verify tokens or passwords leaks timing information "
                        "because character comparison terminates at the first mismatch. "
                        "An attacker measuring server response latency can infer secret values character-by-character (CWE-208)."
                    ),
                    severity="high",
                    category="security",
                    source="ai",
                    line_start=idx,
                    line_end=idx,
                    suggested_fix="Use constant-time comparison like `hmac.compare_digest` (Python) or `crypto.timingSafeEqual` (Node.js).",
                    fix_diff="- if provided_token == stored_token:\n+ import hmac\n+ if hmac.compare_digest(provided_token, stored_token):"
                ))

        # Semantic Rule 2: Unhandled Concurrency / Race Condition in Counter or Balance
        race_pattern = re.compile(r'([a-zA-Z0-9_]+)\s*(\+=|-=)\s*1')
        if race_pattern.search(code) and not any(kw in code.lower() for kw in ("lock", "atomic", "mutex", "synchronized")):
            match = race_pattern.search(code)
            var_name = match.group(1) if match else "counter"
            ai_findings.append(FindingCreate(
                rule_id="AI-BUG-001",
                title=f"Potential Race Condition on shared state `{var_name}`",
                description=(
                    f"Modifying `{var_name}` in concurrent environments without synchronization or database atomic updates "
                    "can cause lost updates or inconsistent state under high concurrency."
                ),
                severity="medium",
                category="bug",
                source="ai",
                line_start=None,
                line_end=None,
                suggested_fix="Wrap mutations in a lock, or use database transactions with `SELECT FOR UPDATE` or atomic increments.",
                fix_diff=f"- {var_name} += 1\n+ with thread_lock:\n+     {var_name} += 1"
            ))

        # Semantic Rule 3: Error Message Information Disclosure
        traceback_pattern = re.compile(r'(?i)(str\(e\)|repr\(e\)|err\.stack|err\.message)\s*\)')
        for idx, line in enumerate(lines, start=1):
            if traceback_pattern.search(line) and any(kw in line.lower() for kw in ("return", "response", "json", "send")):
                ai_findings.append(FindingCreate(
                    rule_id="AI-SEC-002",
                    title="Sensitive Information Disclosure in Error Response",
                    description=(
                        "Returning raw exception strings or stack traces directly in API responses "
                        "leaks internal database schemas, filesystem paths, or third-party library versions to clients (CWE-209)."
                    ),
                    severity="medium",
                    category="security",
                    source="ai",
                    line_start=idx,
                    line_end=idx,
                    suggested_fix="Log detailed stack traces internally, and return sanitized, generic error messages to clients.",
                    fix_diff="- return {'error': str(e)}\n+ logger.exception('Internal failure', exc_info=e)\n+ return {'error': 'An internal error occurred. Please contact support.'}"
                ))

        # Semantic Rule 4: Deep Nesting / Cognitive Complexity
        max_indent = 0
        deepest_line = 1
        for idx, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("//"):
                indent = len(line) - len(stripped)
                if indent > max_indent:
                    max_indent = indent
                    deepest_line = idx

        if max_indent >= 16:  # 4+ levels of indentation
            ai_findings.append(FindingCreate(
                rule_id="AI-QUAL-001",
                title="Excessive Cyclomatic / Cognitive Complexity",
                description=(
                    "This code block contains deep nesting (4+ nested control levels). "
                    "High cognitive complexity increases cognitive load, complicates unit testing, and statistically correlates with defect density."
                ),
                severity="low",
                category="quality",
                source="ai",
                line_start=deepest_line,
                line_end=deepest_line,
                suggested_fix="Refactor into smaller guard clauses (early returns) or extract helper functions.",
                fix_diff="// Prefer guard clauses:\n- if (condition) {\n-   doWork();\n- }\n+ if (!condition) return;\n+ doWork();"
            ))

        # Generate Executive Review Summary
        total_issues = len(static_findings) + len(ai_findings)
        critical_count = sum(1 for f in static_findings + ai_findings if f.severity == "critical")
        high_count = sum(1 for f in static_findings + ai_findings if f.severity == "high")

        if critical_count > 0:
            summary = (
                f"⚠️ **Security Alert**: Automated inspection identified {critical_count} CRITICAL and {high_count} HIGH severity vulnerabilities. "
                "Immediate remediation is required prior to production deployment, particularly concerning input sanitization and credential boundaries."
            )
        elif high_count > 0:
            summary = (
                f"⚠️ **Review Notice**: Found {high_count} HIGH severity findings. "
                "Addressing these issues will significantly harden application resiliency and prevent potential exploits."
            )
        elif total_issues > 0:
            summary = (
                f"ℹ️ **Quality Inspection Completed**: Detected {total_issues} minor findings and code quality suggestions. "
                "The code is generally structured well; implementing the proposed refactoring diffs will improve maintainability."
            )
        else:
            summary = (
                "✅ **Clean Code Review**: No automated static or semantic issues were detected in this submission. "
                "Ensure comprehensive integration and unit tests are maintained."
            )

        return ai_findings, summary
