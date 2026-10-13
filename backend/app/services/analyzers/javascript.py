import re
from typing import List, Optional
from app.services.analyzers.base import BaseAnalyzer, AnalysisResult
from app.schemas.review import FindingCreate

PATTERNS = [
    {
        "id": "SEC-JS-001",
        "regex": re.compile(r'(\.innerHTML|\.outerHTML|document\.write)\s*='),
        "title": "Cross-Site Scripting (XSS) via DOM injection",
        "description": "Assigning untrusted content to `.innerHTML`, `.outerHTML`, or `document.write` allows script execution in client browsers (CWE-79).",
        "severity": "high",
        "category": "security",
        "fix": "Use `.textContent` or sanitize with DOMPurify.",
        "diff": "- element.innerHTML = userInput;\n+ element.textContent = userInput;"
    },
    {
        "id": "SEC-JS-002",
        "regex": re.compile(r'\b(eval\s*\(|new\s+Function\s*\()'),
        "title": "Dangerous dynamic execution with `eval` or `Function`",
        "description": "Dynamic evaluation executes strings as code, leading to arbitrary JavaScript code execution (CWE-95).",
        "severity": "critical",
        "category": "security",
        "fix": "Use structured JSON parsers or explicit functional mapping.",
        "diff": "- const res = eval(expr);\n+ const res = JSON.parse(expr);"
    },
    {
        "id": "SEC-JS-003",
        "regex": re.compile(r'(__proto__|constructor\.prototype)'),
        "title": "Prototype Pollution risk",
        "description": "Mutating object prototypes directly enables Prototype Pollution (CWE-1321), corrupting default properties application-wide.",
        "severity": "high",
        "category": "security",
        "fix": "Reject `__proto__` and `constructor` keys, or use `Object.create(null)`.",
        "diff": "- target[key] = source[key];\n+ if (key !== '__proto__' && key !== 'constructor') target[key] = source[key];"
    },
    {
        "id": "SEC-JS-004",
        "regex": re.compile(r'Math\.random\(\)\s*(\*|\+)'),
        "title": "Cryptographically weak randomness (`Math.random`)",
        "description": "`Math.random()` is not a CSPRNG and is predictable. Never use it for tokens or passwords (CWE-338).",
        "severity": "medium",
        "category": "security",
        "fix": "Use `crypto.randomUUID()` or `crypto.getRandomValues()`.",
        "diff": "- const token = Math.random().toString(36);\n+ const token = crypto.randomUUID();"
    },
    {
        "id": "BUG-JS-001",
        "regex": re.compile(r'(?<![=!><])\s*(==|!=)\s*(?![=])'),
        "title": "Loose equality operator (`==` or `!=`) introduces type coercion",
        "description": "Loose equality coerces types implicitly (e.g. `\"0\" == false`), leading to unexpected logic flaws.",
        "severity": "low",
        "category": "bug",
        "fix": "Use strict equality `===` or `!==`.",
        "diff": "- if (role == 'admin')\n+ if (role === 'admin')"
    },
    {
        "id": "BUG-JS-003",
        "regex": re.compile(r'typeof\s+[a-zA-Z0-9_.]+\s*===?\s*["\']NaN["\']'),
        "title": "Invalid `typeof` check for NaN",
        "description": "`typeof NaN` evaluates to `'number'`. Comparing `typeof x === 'NaN'` will always evaluate to false.",
        "severity": "high",
        "category": "bug",
        "fix": "Use `Number.isNaN(val)` instead of `typeof` check.",
        "diff": "- if (typeof val === 'NaN')\n+ if (Number.isNaN(val))"
    },
    {
        "id": "BUG-JS-004",
        "regex": re.compile(r'if\s*\(\s*[a-zA-Z0-9_.]+\s*=\s*[^=]'),
        "title": "Accidental assignment in conditional statement",
        "description": "Using single assignment `=` inside `if (...)` assigns the variable rather than testing equality.",
        "severity": "high",
        "category": "bug",
        "fix": "Use comparison `===` instead of assignment `=`.",
        "diff": "- if (user = current)\n+ if (user === current)"
    },
    {
        "id": "SEC-JS-005",
        "regex": re.compile(r'(?i)(jwt_secret|api_key|token|auth_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']'),
        "title": "Hardcoded secret or credential detected",
        "description": "Hardcoding API credentials in JavaScript exposes tokens to clients or VCS commits (CWE-798).",
        "severity": "critical",
        "category": "security",
        "fix": "Store secrets in environment variables via `process.env`.",
        "diff": "- const SECRET = 'sk_live_...';\n+ const SECRET = process.env.API_SECRET;"
    },
    {
        "id": "BUG-JS-005",
        "regex": re.compile(r'\.then\s*\([^)]*\)(?!\s*\.catch)'),
        "title": "Unhandled Promise Rejection Risk (Missing `.catch()`)",
        "description": "Calling `.then()` on an asynchronous Promise without a chained `.catch()` rejection handler risks unhandled promise rejections.",
        "severity": "medium",
        "category": "bug",
        "fix": "Append `.catch(err => ...)` to handle potential asynchronous rejections.",
        "diff": "- fetch(url).then(res => res.json());\n+ fetch(url).then(res => res.json()).catch(err => handleError(err));"
    },
    {
        "id": "BUG-JS-006",
        "regex": re.compile(r'document\.(getElementById|querySelector)\s*\([^)]*\)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)'),
        "title": "Unsafe DOM Property Access without Null Check (TypeError Risk)",
        "description": "DOM query functions return `null` if the target element is missing. Directly accessing properties without checking for `null` throws a runtime `TypeError`.",
        "severity": "medium",
        "category": "bug",
        "fix": "Use optional chaining `?.` or verify the element is non-null.",
        "diff": "- const val = document.getElementById('input').value;\n+ const val = document.getElementById('input')?.value;"
    }
]

TS_PATTERNS = [
    {
        "id": "TS-QUAL-001",
        "regex": re.compile(r':\s*any\b|as\s+any\b'),
        "title": "Permissive `any` type usage compromises type safety",
        "description": "Using `any` suppresses TypeScript's static type checker, creating potential runtime TypeError risks.",
        "severity": "low",
        "category": "quality",
        "fix": "Use a strongly typed interface, generic, or `unknown` with type narrowing.",
        "diff": "- function process(data: any): any\n+ function process<T>(data: T): T"
    },
    {
        "id": "TS-BUG-001",
        "regex": re.compile(r'[a-zA-Z0-9_]+\!(\.|\()'),
        "title": "Dangerous non-null assertion operator (`!`)",
        "description": "Forcing non-null assertion (`obj!.prop`) bypasses null-safety and triggers runtime errors if null.",
        "severity": "medium",
        "category": "bug",
        "fix": "Use optional chaining `?.` or explicit null guards.",
        "diff": "- const val = user!.profile.name;\n+ const val = user?.profile?.name;"
    },
    {
        "id": "TS-QUAL-002",
        "regex": re.compile(r'//\s*@ts-(ignore|nocheck)\b'),
        "title": "Suppression of TypeScript Compiler Diagnostics via `@ts-ignore` / `@ts-nocheck`",
        "description": "Using `@ts-ignore` or `@ts-nocheck` disables compiler verification, masking type safety issues and runtime defects.",
        "severity": "low",
        "category": "quality",
        "fix": "Resolve the underlying type mismatch or declare proper types instead of suppressing the compiler.",
        "diff": "- // @ts-ignore\n- process(item);\n+ process(item as ExpectedType);"
    }
]


class JavaScriptAnalyzer(BaseAnalyzer):
    def __init__(self, is_typescript: bool = False):
        self._is_ts = is_typescript

    @property
    def language(self) -> str:
        return "typescript" if self._is_ts else "javascript"

    @property
    def name(self) -> str:
        return "TypeScript Static Analyzer" if self._is_ts else "JavaScript Static Analyzer"

    @property
    def features(self) -> List[str]:
        base = [
            "Brace & Parenthesis Syntax Balance Check",
            "Cross-Site Scripting (XSS) DOM Vulnerability Scanning",
            "Dynamic Code Execution (eval, Function) Detection",
            "Prototype Pollution Guard",
            "Weak Cryptographic Randomness Detection",
            "Type Coercion & Strict Equality Auditing",
            "Hardcoded Credentials & API Token Inspection"
        ]
        if self._is_ts:
            base.extend([
                "TypeScript `any` Type Abuse Detection",
                "Risky Non-Null Assertion Operator Audit"
            ])
        return base

    @property
    def limitations(self) -> str:
        return "Static regex and token heuristics. Full TypeScript compiler diagnostics require tsconfig.json and loaded node_modules."

    def analyze(self, code: str) -> AnalysisResult:
        findings: List[FindingCreate] = []
        lines = code.splitlines()

        # Step 1: Structural syntax balance
        stack = []
        pairs = {')': '(', '}': '{', ']': '['}
        for idx, line in enumerate(lines, start=1):
            for col, ch in enumerate(line, start=1):
                if ch in "({[":
                    stack.append((ch, idx, col))
                elif ch in ")}]":
                    if not stack or stack[-1][0] != pairs[ch]:
                        findings.append(FindingCreate(
                            rule_id="SYN-JS-001",
                            title=f"Mismatched closing bracket `{ch}`",
                            description=f"Syntax error at line {idx}, col {col}: unexpected closing `{ch}` without matching opener.",
                            severity="critical",
                            category="syntax",
                            source="static",
                            line_start=idx,
                            line_end=idx,
                            column_start=col,
                            evidence=line.strip(),
                            confidence="high",
                            suggested_fix="Verify bracket and parentheses pairing."
                        ))
                    else:
                        stack.pop()

        if stack:
            unclosed_ch, unclosed_line, unclosed_col = stack[-1]
            findings.append(FindingCreate(
                rule_id="SYN-JS-002",
                title=f"Unclosed opening bracket `{unclosed_ch}`",
                description=f"Syntax error: bracket `{unclosed_ch}` opened at line {unclosed_line}, col {unclosed_col} is never closed.",
                severity="critical",
                category="syntax",
                source="static",
                line_start=unclosed_line,
                line_end=unclosed_line,
                column_start=unclosed_col,
                evidence=lines[unclosed_line - 1].strip() if 1 <= unclosed_line <= len(lines) else None,
                confidence="high",
                suggested_fix="Close opening block with corresponding closing bracket."
            ))

        # Step 2: Line by line pattern analysis
        active_patterns = PATTERNS + (TS_PATTERNS if self._is_ts else [])
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Ignore standard comments except TypeScript compiler directives
            if (stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")) and not ("@ts-ignore" in stripped or "@ts-nocheck" in stripped):
                continue

            for pattern_def in active_patterns:
                match = pattern_def["regex"].search(line)
                if match:
                    findings.append(FindingCreate(
                        rule_id=pattern_def["id"],
                        title=pattern_def["title"],
                        description=pattern_def["description"],
                        severity=pattern_def["severity"],
                        category=pattern_def["category"],
                        source="static",
                        line_start=idx,
                        line_end=idx,
                        column_start=match.start() + 1,
                        column_end=match.end() + 1,
                        evidence=stripped,
                        confidence="high",
                        suggested_fix=pattern_def["fix"],
                        fix_diff=pattern_def.get("diff")
                    ))

        status = "completed_with_limitations" if any(f.category == "syntax" for f in findings) else "completed"
        coverage = f"Checked {len(lines)} lines of {self.language.upper()} code against {len(active_patterns)} rule checks."

        return AnalysisResult(
            status=status,
            language=self.language,
            findings=findings,
            coverage_summary=coverage,
            limitations=self.limitations
        )
