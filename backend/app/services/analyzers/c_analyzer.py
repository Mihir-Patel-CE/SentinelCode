import re
from typing import List, Optional
from app.services.analyzers.base import BaseAnalyzer, AnalysisResult
from app.services.analyzers.sandbox import CompilerSandbox, CompilerNotFoundError
from app.services.analyzers.clang_parser import ClangDiagnosticParser
from app.schemas.review import FindingCreate
from app.core.logging import logger


C_STATIC_RULES = [
    {
        "id": "SEC-C-001",
        "regex": re.compile(r'\bgets\s*\('),
        "title": "Inherently Dangerous Function `gets()` (CWE-242)",
        "description": (
            "The `gets()` function does not check buffer boundaries and cannot be used safely. "
            "It is susceptible to trivial buffer overflows leading to arbitrary code execution. "
            "It was formally removed from ISO C11 (CWE-242)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Replace `gets(buf)` with `fgets(buf, sizeof(buf), stdin)`.",
        "diff": "- gets(buffer);\n+ if (fgets(buffer, sizeof(buffer), stdin) == NULL) {\n+     /* handle input error */\n+ }"
    },
    {
        "id": "SEC-C-002",
        "regex": re.compile(r'\bstrcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_\"\'.]+)'),
        "title": "Unbounded String Copy `strcpy()` (CWE-120)",
        "description": (
            "The `strcpy()` function performs an unbounded memory copy until a NUL byte is reached. "
            "If the source string exceeds the target buffer capacity, stack or heap memory is corrupted (CWE-120)."
        ),
        "severity": "high",
        "category": "security",
        "fix": "Use bounded alternatives such as `strncpy(dest, src, sizeof(dest) - 1)` or `snprintf(dest, sizeof(dest), \"%s\", src)`.",
        "diff": "- strcpy(dest, src);\n+ strncpy(dest, src, sizeof(dest) - 1);\n+ dest[sizeof(dest) - 1] = '\\0';"
    },
    {
        "id": "SEC-C-003",
        "regex": re.compile(r'\bstrcat\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_\"\'.]+)'),
        "title": "Unbounded String Concatenation `strcat()` (CWE-120)",
        "description": (
            "The `strcat()` function does not check remaining space in the destination buffer, "
            "risking buffer overflow if total length exceeds buffer bounds (CWE-120)."
        ),
        "severity": "high",
        "category": "security",
        "fix": "Use bounded concatenation like `strncat(dest, src, sizeof(dest) - strlen(dest) - 1)` or `snprintf`.",
        "diff": "- strcat(dest, src);\n+ strncat(dest, src, sizeof(dest) - strlen(dest) - 1);"
    },
    {
        "id": "SEC-C-004",
        "regex": re.compile(r'\bsprintf\s*\(\s*([a-zA-Z0-9_]+)\s*,'),
        "title": "Unchecked Formatted String Output `sprintf()` (CWE-120)",
        "description": (
            "`sprintf()` writes arbitrary formatted bytes into a buffer without specifying max destination size, "
            "creating classical buffer overflow vulnerabilities (CWE-120 / CWE-134)."
        ),
        "severity": "high",
        "category": "security",
        "fix": "Replace `sprintf()` with `snprintf(buf, sizeof(buf), ...)`.",
        "diff": '- sprintf(buffer, "%s %d", name, id);\n+ snprintf(buffer, sizeof(buffer), "%s %d", name, id);'
    },
    {
        "id": "SEC-C-005",
        "regex": re.compile(r'\bprintf\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)'),
        "title": "Format String Vulnerability in `printf()` (CWE-134)",
        "description": (
            "Passing variable data directly as the format argument of `printf(str)` allows attackers "
            "to supply format specifiers (%x, %s, %n) to read stack memory or overwrite arbitrary addresses (CWE-134)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Pass a constant format string literal: `printf(\"%s\", str)`.",
        "diff": '- printf(user_input);\n+ printf("%s", user_input);'
    },
    {
        "id": "SEC-C-006",
        "regex": re.compile(r'\bscanf\s*\(\s*["\']%s["\']\s*,'),
        "title": "Unbounded Input Format Specifier in `scanf()` (CWE-120)",
        "description": (
            "`scanf(\"%s\", buf)` reads characters without an upper bound until whitespace is encountered, "
            "guaranteeing buffer overflow if user input exceeds destination buffer size (CWE-120)."
        ),
        "severity": "high",
        "category": "security",
        "fix": "Specify field width in format specifier or use `fgets()`.",
        "diff": '- scanf("%s", buffer);\n+ scanf("%99s", buffer); /* assuming buffer is char[100] */'
    },
    {
        "id": "SEC-C-007",
        "regex": re.compile(r'(?i)(password|secret|api_key|token|private_key)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'),
        "title": "Hardcoded Credential or API Secret in C Source (CWE-798)",
        "description": (
            "Hardcoding credentials or API tokens into C source files embeds secrets directly into compiled binaries, "
            "readily extracted via binary analysis tools or `strings` (CWE-798)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Retrieve secrets at runtime from environment variables using `getenv()` or secure keyrings.",
        "diff": '- const char *key = "secret_token_12345";\n+ const char *key = getenv("API_SECRET_KEY");'
    },
    {
        "id": "BUG-C-004",
        "regex": re.compile(r'\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\);[\s\S]{1,120}\bfree\s*\(\s*\1\s*\);'),
        "title": "Double Free Vulnerability (CWE-415)",
        "description": (
            "Calling `free()` twice on the same memory pointer without reallocating causes memory heap corruption "
            "and exploitable write-what-where conditions (CWE-415)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Set pointer to NULL immediately after calling free: `free(ptr); ptr = NULL;`.",
        "diff": '- free(ptr);\n- free(ptr);\n+ free(ptr);\n+ ptr = NULL;'
    }
]


class CAnalyzer(BaseAnalyzer):
    """
    Production-grade C static analyzer utilizing Clang compiler diagnostics (-fsyntax-only),
    Clang Static Analysis (--analyze), and deterministic security pattern inspection.
    """

    def __init__(self, compiler_cmd: str = "clang", timeout: float = 5.0):
        self._compiler_cmd = compiler_cmd
        self._sandbox = CompilerSandbox(timeout_seconds=timeout)

    @property
    def language(self) -> str:
        return "c"

    @property
    def name(self) -> str:
        return "C Clang Compiler Diagnostic & Static Security Analyzer"

    @property
    def features(self) -> List[str]:
        return [
            "Clang -fsyntax-only Compiler Syntax Verification",
            "Clang Static Analyzer Path-Sensitive Diagnostics (core.NullDereference)",
            "Array Out-of-Bounds Detection (-Warray-bounds)",
            "Unsafe Buffer Operations Audit (gets, strcpy, strcat, sprintf)",
            "Format String Vulnerability Detection (printf non-literal format, CWE-134)",
            "Memory Management & Double Free Inspection (CWE-415, CWE-401)",
            "Uninitialized Variable Detection (-Wuninitialized)",
            "Hardcoded Credential & Token Inspection (CWE-798)",
            "Sandboxed Compilation Isolation with Resource Limits"
        ]

    @property
    def limitations(self) -> str:
        return (
            "Analyzes single-file C snippets without full makefile/CMake target dependencies. "
            "External system library headers and macro definitions outside standard libc must be provided inline."
        )

    def analyze(self, code: str) -> AnalysisResult:
        # Check if compiler is available in the deployment environment
        if not self._sandbox.is_available(self._compiler_cmd):
            return AnalysisResult(
                status="failed",
                language="c",
                findings=[],
                coverage_summary="Analyzer unavailable: Compiler toolchain is unavailable in this environment.",
                limitations=self.limitations,
                error_message=(
                    f"Analyzer unavailable: Clang compiler/analyzer executable '{self._compiler_cmd}' is not available "
                    "in the system PATH. Please verify LLVM/Clang installation."
                )
            )

        findings: List[FindingCreate] = []
        has_syntax_errors = False

        # Pass 1: Syntax & compiler warnings via Clang
        try:
            res_syntax = self._sandbox.execute_in_sandbox(
                executable_name=self._compiler_cmd,
                arguments=[
                    "-fsyntax-only",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Warray-bounds",
                    "-Wnull-dereference",
                    "-Wuninitialized",
                    "-Wformat=2",
                    "-Wdeprecated-declarations",
                    "-x", "c",
                    "{INPUT_FILE}"
                ],
                code=code,
                filename="snippet.c"
            )
            if res_syntax.timed_out:
                return AnalysisResult(
                    status="failed",
                    language="c",
                    findings=[],
                    coverage_summary="Analysis failed: Compiler execution timed out.",
                    limitations=self.limitations,
                    error_message=f"Analyzer timed out after {self._sandbox.timeout_seconds}s."
                )
            syntax_findings = ClangDiagnosticParser.parse(res_syntax.stderr, code)
            findings.extend(syntax_findings)
            if any(f.category == "syntax" for f in syntax_findings):
                has_syntax_errors = True
        except CompilerNotFoundError as e:
            return AnalysisResult(
                status="failed",
                language="c",
                findings=[],
                coverage_summary="Analysis failed: Compiler toolchain not found.",
                error_message=str(e)
            )
        except Exception as e:
            logger.error(f"Error during C syntax analysis pass: {e}")

        # Pass 2: Clang Static Analyzer pass (if no fatal syntax errors)
        if not has_syntax_errors:
            try:
                res_sa = self._sandbox.execute_in_sandbox(
                    executable_name=self._compiler_cmd,
                    arguments=[
                        "--analyze",
                        "-Xanalyzer",
                        "-analyzer-output=text",
                        "-x", "c",
                        "{INPUT_FILE}"
                    ],
                    code=code,
                    filename="snippet.c"
                )
                if not res_sa.timed_out:
                    sa_findings = ClangDiagnosticParser.parse(res_sa.stderr, code)
                    findings.extend(sa_findings)
            except Exception as e:
                logger.debug(f"Clang --analyze pass skipped or encountered error: {e}")

        # Pass 3: Complementary Static Security Rules (buffer overruns, dangerous APIs, hardcoded creds)
        code_lines = code.splitlines()
        for rule in C_STATIC_RULES:
            pattern: re.Pattern = rule["regex"]
            if rule["id"] in ("BUG-C-004",):
                match = pattern.search(code)
                if match:
                    line_no = code[:match.start()].count("\n") + 1
                    col_start = match.start() - code.rfind("\n", 0, match.start())
                    evidence = code_lines[line_no - 1].strip() if line_no <= len(code_lines) else None
                    findings.append(FindingCreate(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=rule["category"],
                        source="static",
                        line_start=line_no,
                        line_end=line_no,
                        column_start=max(1, col_start),
                        column_end=max(1, col_start + len(match.group(0))),
                        evidence=evidence,
                        confidence="high",
                        suggested_fix=rule.get("fix"),
                        fix_diff=rule.get("diff")
                    ))
            else:
                for idx, line in enumerate(code_lines, start=1):
                    m = pattern.search(line)
                    if m:
                        findings.append(FindingCreate(
                            rule_id=rule["id"],
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            category=rule["category"],
                            source="static",
                            line_start=idx,
                            line_end=idx,
                            column_start=m.start() + 1,
                            column_end=m.end() + 1,
                            evidence=line.strip(),
                            confidence="high",
                            suggested_fix=rule.get("fix"),
                            fix_diff=rule.get("diff")
                        ))

        # Check for Out-of-bounds in static loops / constant array indexing
        arr_decl_re = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d+)\s*\]')
        arrays = {}
        for idx, line in enumerate(code_lines, start=1):
            for m in arr_decl_re.finditer(line):
                arrays[m.group(1)] = (int(m.group(2)), idx)

        for arr_name, (size, decl_line) in arrays.items():
            access_re = re.compile(rf'\b{arr_name}\s*\[\s*(\d+)\s*\]')
            for idx, line in enumerate(code_lines, start=1):
                if idx == decl_line:
                    continue
                for am in access_re.finditer(line):
                    idx_val = int(am.group(1))
                    if idx_val >= size:
                        findings.append(FindingCreate(
                            rule_id="BUG-C-OOB-002",
                            title=f"Static Array Bound Violation on `{arr_name}` (CWE-119)",
                            description=(
                                f"Array `{arr_name}` was declared with capacity {size}, but is accessed at static index {idx_val} "
                                f"on line {idx}. This constitutes a buffer overflow or out-of-bounds read/write (CWE-119 / CWE-787)."
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
                            suggested_fix=f"Ensure index is between 0 and {size - 1}."
                        ))

        # Check for unchecked malloc/calloc/realloc calls
        alloc_re = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([a-zA-Z0-9_*\s]+\)\s*)?(malloc|calloc|realloc)\s*\(')
        for idx, line in enumerate(code_lines, start=1):
            m = alloc_re.search(line)
            if m:
                var_name = m.group(1)
                alloc_fn = m.group(2)
                # Check next 8 lines for a NULL check
                following = "\n".join(code_lines[idx:min(len(code_lines), idx + 8)])
                null_check = re.search(rf'if\s*\(\s*(!{var_name}|{var_name}\s*==\s*NULL|NULL\s*==\s*{var_name})\b', following)
                if not null_check:
                    findings.append(FindingCreate(
                        rule_id="BUG-C-NULL-002",
                        title=f"Unchecked `{alloc_fn}()` Return Value for `{var_name}` (CWE-476)",
                        description=(
                            f"`{alloc_fn}()` returns NULL if memory allocation fails. Dereferencing `{var_name}` without "
                            "verifying it is non-null risks a crash or denial of service under memory pressure (CWE-476 / CWE-252)."
                        ),
                        severity="high",
                        category="bug",
                        source="static",
                        line_start=idx,
                        line_end=idx,
                        column_start=m.start() + 1,
                        column_end=m.end() + 1,
                        evidence=line.strip(),
                        confidence="medium",
                        suggested_fix=f"Check for allocation failure: `if ({var_name} == NULL) {{ /* handle error */ }}`",
                        fix_diff=f"- {var_name} = {alloc_fn}(...);\n+ {var_name} = {alloc_fn}(...);\n+ if ({var_name} == NULL) return -1;"
                    ))

        # Check for Use-After-Free in C: free(ptr); followed by *ptr or ptr-> or ptr[...]
        free_re = re.compile(r'\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*;')
        for idx, line in enumerate(code_lines, start=1):
            for fm in free_re.finditer(line):
                freed_var = fm.group(1)
                for follow_idx in range(idx, min(len(code_lines), idx + 20)):
                    follow_line = code_lines[follow_idx]
                    if re.search(rf'(?<!\*)\b{freed_var}\s*=\s*', follow_line):
                        break
                    uaf_match = re.search(rf'(\*\s*{freed_var}\b|{freed_var}\s*->|{freed_var}\s*\[)', follow_line)
                    if uaf_match:
                        findings.append(FindingCreate(
                            rule_id="SEC-C-UAF-001",
                            title=f"Use-After-Free Vulnerability on `{freed_var}` (CWE-416)",
                            description=(
                                f"Pointer `{freed_var}` was deallocated via `free()` on line {idx}, but accessed or dereferenced "
                                f"on line {follow_idx + 1} (`{follow_line.strip()}`). Accessing deallocated memory invokes undefined behavior "
                                "and leads to memory corruption or arbitrary code execution (CWE-416)."
                            ),
                            severity="critical",
                            category="security",
                            source="static",
                            line_start=follow_idx + 1,
                            line_end=follow_idx + 1,
                            column_start=uaf_match.start() + 1,
                            column_end=uaf_match.end() + 1,
                            evidence=follow_line.strip(),
                            confidence="high",
                            suggested_fix=f"Do not access `{freed_var}` after calling free. Set `{freed_var} = NULL;` immediately.",
                            fix_diff=f"- free({freed_var});\n+ free({freed_var});\n+ {freed_var} = NULL;"
                        ))
                        break

        # Check for dynamic memory leak in C without free or return
        for idx, line in enumerate(code_lines, start=1):
            m = alloc_re.search(line)
            if m:
                var_name = m.group(1)
                alloc_fn = m.group(2)
                if (not re.search(rf'\bfree\s*\(\s*{var_name}\s*\)', code) and
                    not re.search(rf'\breturn\s+(?:\([^)]*\)\s*)?{var_name}\b', code)):
                    findings.append(FindingCreate(
                        rule_id="BUG-C-MEM-001",
                        title=f"Potential Dynamic Memory Leak on `{var_name}` (CWE-401)",
                        description=(
                            f"`{var_name}` is dynamically allocated via `{alloc_fn}()` on line {idx} without a corresponding `free()`. "
                            "Failing to release dynamically allocated memory before going out of scope leads to memory leaks and resource exhaustion (CWE-401)."
                        ),
                        severity="high",
                        category="bug",
                        source="static",
                        line_start=idx,
                        line_end=idx,
                        column_start=m.start() + 1,
                        column_end=m.end() + 1,
                        evidence=line.strip(),
                        confidence="medium",
                        suggested_fix=f"Release allocated memory with `free({var_name});` before pointer goes out of scope.",
                        fix_diff=f"+ free({var_name});\n+ {var_name} = NULL;"
                    ))

        # Deduplicate findings by rule_id and line
        deduped: List[FindingCreate] = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_start)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Status calculation
        status = "completed_with_limitations" if has_syntax_errors else "completed"
        coverage_summary = (
            f"Clang compiler verification completed with syntax limitations ({len(deduped)} findings)."
            if has_syntax_errors
            else f"Clang compiler diagnostics & deterministic security analysis completed ({len(deduped)} findings)."
        )

        return AnalysisResult(
            status=status,
            language="c",
            findings=deduped,
            coverage_summary=coverage_summary,
            limitations=self.limitations
        )
