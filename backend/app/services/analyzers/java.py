import re
from typing import List
from app.services.analyzers.base import BaseAnalyzer, AnalysisResult
from app.schemas.review import FindingCreate

JAVA_PATTERNS = [
    {
        "id": "SEC-JV-001",
        "regex": re.compile(r'(?i)(executeQuery|executeUpdate)\s*\(\s*["\'].*\+\s*[a-zA-Z0-9_]+'),
        "title": "SQL Injection in JDBC query execution",
        "description": "Concatenating variables into JDBC `Statement.executeQuery()` allows SQL Injection (CWE-89).",
        "severity": "critical",
        "category": "security",
        "fix": "Use `PreparedStatement` with parameterized placeholders (`?`).",
        "diff": '- stmt.executeQuery("SELECT * FROM tbl WHERE id = " + id);\n+ PreparedStatement ps = conn.prepareStatement("SELECT * FROM tbl WHERE id = ?");\n+ ps.setString(1, id);\n+ ps.executeQuery();'
    },
    {
        "id": "SEC-JV-002",
        "regex": re.compile(r'new\s+File\s*\(\s*([a-zA-Z0-9_]+|[a-zA-Z0-9_.]+\s*\+\s*[a-zA-Z0-9_.]+)'),
        "title": "Potential Path Traversal via unvalidated File path",
        "description": "Instantiating `File` with untrusted input without path normalization allows Path Traversal (CWE-22).",
        "severity": "high",
        "category": "security",
        "fix": "Normalize path with `toPath().normalize()` and verify `startsWith(baseDir)`.",
        "diff": "- File f = new File(baseDir + path);\n+ Path p = Paths.get(baseDir, path).normalize();\n+ if (!p.startsWith(baseDir)) throw new SecurityException('Traversal detected');"
    },
    {
        "id": "SEC-JV-003",
        "regex": re.compile(r'(?i)MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1)["\']\s*\)'),
        "title": "Insecure MessageDigest algorithm (`MD5` or `SHA-1`)",
        "description": "`MD5` and `SHA-1` are cryptographically broken (CWE-328). Use `SHA-256` or `SHA-512`.",
        "severity": "medium",
        "category": "security",
        "fix": "Use `MessageDigest.getInstance(\"SHA-256\")`.",
        "diff": '- MessageDigest md = MessageDigest.getInstance("MD5");\n+ MessageDigest md = MessageDigest.getInstance("SHA-256");'
    },
    {
        "id": "BUG-JV-001",
        "regex": re.compile(r'(?<![=!><])\s*==\s*(?![=])\s*["\']|["\']\s*==\s*(?![=])'),
        "title": "String comparison using reference equality `==`",
        "description": "In Java, `==` tests object reference equality rather than String value equality. Use `.equals()`.",
        "severity": "medium",
        "category": "bug",
        "fix": "Use `.equals()` or `Objects.equals()`.",
        "diff": '- if (status == "ACTIVE")\n+ if ("ACTIVE".equals(status))'
    },
    {
        "id": "BUG-JV-002",
        "regex": re.compile(r'catch\s*\([a-zA-Z0-9_]+Exception\s+[a-zA-Z0-9_]+\)\s*\{\s*\}'),
        "title": "Empty catch block suppresses exceptions",
        "description": "Silently swallowing exceptions prevents proper error handling and masks failures.",
        "severity": "low",
        "category": "quality",
        "fix": "Log exception or rethrow with contextual information.",
        "diff": "- catch (Exception e) {}\n+ catch (Exception e) { logger.error(\"Operation failed\", e); }"
    },
    {
        "id": "SEC-JV-004",
        "regex": re.compile(r'(?i)(password|secret|api_key)\s*=\s*["\']([a-zA-Z0-9_\-\.]{12,})["\']'),
        "title": "Hardcoded credential detected in Java source",
        "description": "Hardcoding secrets into Java classes allows extraction via bytecode decompilation (CWE-798).",
        "severity": "critical",
        "category": "security",
        "fix": "Read credentials from environment variables or configuration properties.",
        "diff": '- String pass = "secret123";\n+ String pass = System.getenv("DB_PASSWORD");'
    },
    {
        "id": "SEC-JV-005",
        "regex": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\'].*\+\s*[a-zA-Z0-9_]+'),
        "title": "Command Injection in `Runtime.exec()` (CWE-78)",
        "description": "Concatenating untrusted inputs directly into `Runtime.getRuntime().exec()` allows arbitrary OS command injection (CWE-78).",
        "severity": "critical",
        "category": "security",
        "fix": "Use `ProcessBuilder` with separate argument arrays and input validation.",
        "diff": '- Runtime.getRuntime().exec("cmd " + arg);\n+ ProcessBuilder pb = new ProcessBuilder("cmd", arg);'
    },
    {
        "id": "BUG-JV-RES-001",
        "regex": re.compile(r'\b(FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+\1\b'),
        "title": "Unclosed Resource Stream / Potential Resource Leak (CWE-772)",
        "description": "Resource stream instantiated without try-with-resources block or `.close()` cleanup causes file handle leaks (CWE-772 / CWE-404).",
        "severity": "high",
        "category": "bug",
        "fix": "Use try-with-resources: `try (BufferedReader br = new BufferedReader(...)) { ... }`.",
        "diff": "- BufferedReader br = new BufferedReader(...);\n+ try (BufferedReader br = new BufferedReader(...)) {"
    }
]


class JavaAnalyzer(BaseAnalyzer):
    @property
    def language(self) -> str:
        return "java"

    @property
    def name(self) -> str:
        return "Java Static Heuristic Analyzer"

    @property
    def features(self) -> List[str]:
        return [
            "Java Bracket Syntax Balance Check",
            "JDBC SQL Injection Pattern Inspection",
            "Path Traversal via File Constructor Audit",
            "String Reference Equality vs .equals() Analysis",
            "Weak Cryptographic Hash & Cipher Detection",
            "Empty Catch Exception Suppression Detection",
            "Hardcoded Credential Inspection"
        ]

    @property
    def limitations(self) -> str:
        return "Analyzes single Java source snippets statically. Does not execute javac bytecode compilation or classpath resolution."

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
                            rule_id="SYN-JV-001",
                            title=f"Mismatched bracket `{ch}` in Java code",
                            description=f"Syntax parsing issue at line {idx}, col {col}: unexpected `{ch}`.",
                            severity="critical",
                            category="syntax",
                            source="static",
                            line_start=idx,
                            line_end=idx,
                            column_start=col,
                            evidence=line.strip(),
                            confidence="high",
                            suggested_fix="Ensure all opening and closing braces match."
                        ))
                    else:
                        stack.pop()

        if stack:
            unclosed_ch, unclosed_line, unclosed_col = stack[-1]
            findings.append(FindingCreate(
                rule_id="SYN-JV-002",
                title=f"Unclosed opening bracket `{unclosed_ch}`",
                description=f"Syntax issue: block opened at line {unclosed_line}, col {unclosed_col} is not closed.",
                severity="critical",
                category="syntax",
                source="static",
                line_start=unclosed_line,
                line_end=unclosed_line,
                column_start=unclosed_col,
                evidence=lines[unclosed_line - 1].strip() if 1 <= unclosed_line <= len(lines) else None,
                confidence="high",
                suggested_fix="Close the unclosed code block."
            ))

        # Step 2: Line by line pattern audit
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for pattern_def in JAVA_PATTERNS:
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

        # Step 3: Check static array bound violations
        arr_decl_re = re.compile(r'\b[a-zA-Z0-9_<>]+\[\s*\]\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+[a-zA-Z0-9_]+\s*\[\s*(\d+)\s*\]')
        arrays = {}
        for idx, line in enumerate(lines, start=1):
            for m in arr_decl_re.finditer(line):
                arrays[m.group(1)] = (int(m.group(2)), idx)

        for arr_name, (size, decl_line) in arrays.items():
            access_re = re.compile(rf'\b{arr_name}\s*\[\s*(\d+)\s*\]')
            for idx, line in enumerate(lines, start=1):
                if idx == decl_line:
                    continue
                for am in access_re.finditer(line):
                    idx_val = int(am.group(1))
                    if idx_val >= size:
                        findings.append(FindingCreate(
                            rule_id="BUG-JV-OOB-001",
                            title=f"Static Array Bound Violation on `{arr_name}` (CWE-129)",
                            description=(
                                f"Array `{arr_name}` is declared with length {size}, but accessed at static index {idx_val} "
                                f"on line {idx}. This triggers an `ArrayIndexOutOfBoundsException` at runtime (CWE-129)."
                            ),
                            severity="high",
                            category="bug",
                            source="static",
                            line_start=idx,
                            line_end=idx,
                            column_start=am.start() + 1,
                            column_end=am.end() + 1,
                            evidence=line.strip(),
                            confidence="high",
                            suggested_fix=f"Ensure array index is strictly within 0 and {size - 1}."
                        ))

        # Step 4: Check explicit null pointer dereference
        null_deref_re = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*null\s*;[\s\S]{1,120}\b\1\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)')
        for m in null_deref_re.finditer(code):
            var_name = m.group(1)
            method_or_field = m.group(2)
            deref_idx = m.end()
            line_no = code[:deref_idx].count("\n") + 1
            col_start = deref_idx - code.rfind("\n", 0, deref_idx)
            evidence = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else None
            findings.append(FindingCreate(
                rule_id="BUG-JV-NULL-001",
                title=f"Potential Null Pointer Dereference on `{var_name}` (CWE-476)",
                description=(
                    f"Variable `{var_name}` is assigned `null` but subsequently dereferenced at `.{method_or_field}` "
                    "without null verification. This will trigger a `NullPointerException` (CWE-476)."
                ),
                severity="high",
                category="bug",
                source="static",
                line_start=line_no,
                line_end=line_no,
                column_start=max(1, col_start),
                column_end=max(1, col_start + len(var_name) + len(method_or_field) + 1),
                evidence=evidence,
                confidence="high",
                suggested_fix=f"Ensure `{var_name}` is initialized or checked: `if ({var_name} != null)`."
            ))

        # Deduplicate findings
        deduped: List[FindingCreate] = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_start)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        status = "completed_with_limitations" if any(f.category == "syntax" for f in deduped) else "completed"
        coverage = f"Checked {len(lines)} lines of Java code across {len(JAVA_PATTERNS)} vulnerability and quality rules."

        return AnalysisResult(
            status=status,
            language="java",
            findings=deduped,
            coverage_summary=coverage,
            limitations=self.limitations
        )
