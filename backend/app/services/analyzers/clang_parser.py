import re
from typing import List, Optional, Tuple
from app.schemas.review import FindingCreate


# Matches header: <file>:<line>:<col>: <level>: <message>
DIAGNOSTIC_HEADER_RE = re.compile(
    r'^(?:<source>|<stdin>|.*?):(\d+):(\d+):\s+(fatal error|error|warning|note):\s+(.*)$'
)

# Matches trailing diagnostic flags like [-Warray-bounds] or [core.NullDereference]
FLAG_RE = re.compile(r'\[(-W[a-zA-Z0-9_\-]+|[a-zA-Z0-9_.]+)\]\s*$')


class ClangDiagnosticParser:
    """
    Parses stderr output from Clang compiler passes (-fsyntax-only) and
    Clang Static Analyzer passes (--analyze) into normalized SentinelCode findings.
    """

    @classmethod
    def parse(cls, output: str, code: str) -> List[FindingCreate]:
        findings: List[FindingCreate] = []
        code_lines = code.splitlines()

        current_diag = None
        raw_lines = output.splitlines()

        for raw_line in raw_lines:
            match = DIAGNOSTIC_HEADER_RE.match(raw_line)
            if match:
                # Flush previous diagnostic if pending
                if current_diag:
                    finding = cls._build_finding(current_diag, code_lines)
                    if finding:
                        findings.append(finding)
                
                line_num = int(match.group(1))
                col_num = int(match.group(2))
                level = match.group(3).strip()
                message_part = match.group(4).strip()

                current_diag = {
                    "line": line_num,
                    "col": col_num,
                    "level": level,
                    "message": message_part,
                }
            elif current_diag:
                # Continuation line of diagnostic message
                # If line is not a source code pointer or note header, append to message
                stripped = raw_line.strip()
                if stripped and not stripped.startswith("^") and not stripped.startswith("|") and not DIAGNOSTIC_HEADER_RE.match(raw_line):
                    if not raw_line.startswith("   ") and not re.match(r'^\s*\d+\s*\|', raw_line):
                        current_diag["message"] += " " + stripped

        # Flush last diagnostic
        if current_diag:
            finding = cls._build_finding(current_diag, code_lines)
            if finding:
                findings.append(finding)

        # Deduplicate findings with identical rule_id, line, and column
        deduped: List[FindingCreate] = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_start, f.column_start)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    @classmethod
    def _extract_flag(cls, message: str) -> Tuple[str, Optional[str]]:
        flag_match = FLAG_RE.search(message)
        if flag_match:
            flag = flag_match.group(1).lstrip("-W")
            clean_msg = message[:flag_match.start()].strip()
            return clean_msg, flag
        return message, None

    @classmethod
    def _build_finding(cls, diag: dict, code_lines: List[str]) -> Optional[FindingCreate]:
        level = diag["level"]
        if level == "note":
            # Notes are secondary context, not standalone root findings
            return None

        line = diag["line"]
        col = diag["col"]
        raw_msg = diag["message"]

        clean_msg, flag = cls._extract_flag(raw_msg)

        # Extract source evidence if valid line
        evidence = None
        if 1 <= line <= len(code_lines):
            evidence = code_lines[line - 1].strip()

        # 1. Compilation & Syntax Errors
        if level in ("error", "fatal error"):
            # Requirement 6: Do not label every syntax error as a critical security vulnerability.
            # Distinct category 'syntax', severity 'high' or 'medium'
            return FindingCreate(
                rule_id=f"CLANG-ERR-{flag.upper()}" if flag else "CLANG-ERR-SYNTAX",
                title=f"Compilation / Syntax Error: {clean_msg[:80]}",
                description=(
                    f"Compiler encountered a syntax or declaration error on line {line}, col {col}: {clean_msg}. "
                    "This prevents the code from compiling into valid machine code."
                ),
                severity="high",
                category="syntax",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Correct the syntax, declaration, or missing semicolon at the indicated position.",
                fix_diff=None
            )

        # 2. Warnings - Calibrated Classification
        lower_msg = clean_msg.lower()
        lower_flag = (flag or "").lower()

        # Array Bounds / Out-of-bounds
        if "array-bounds" in lower_flag or "array index" in lower_msg or "past the end of the array" in lower_msg:
            return FindingCreate(
                rule_id="BUG-C-OOB-001",
                title="Array Index Out-of-Bounds Access",
                description=(
                    f"Out-of-bounds memory access detected on line {line}: {clean_msg}. "
                    "Accessing indices beyond array capacity triggers undefined behavior, memory corruption, "
                    "or exploitable information disclosure (CWE-119 / CWE-125)."
                ),
                severity="high",
                category="bug",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Ensure array indices are strictly bounded between 0 and (size - 1).",
                fix_diff=None
            )

        # Null Pointer Dereference
        if "nulldereference" in lower_flag or "null-dereference" in lower_flag or "null pointer" in lower_msg:
            return FindingCreate(
                rule_id="BUG-C-NULL-001",
                title="Null Pointer Dereference Risk",
                description=(
                    f"Dereferencing a pointer that may be null on line {line}: {clean_msg}. "
                    "Dereferencing a null pointer leads to segmentation fault, immediate application crash, "
                    "or denial of service (CWE-476)."
                ),
                severity="high",
                category="bug",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Validate pointer validity before dereferencing: `if (ptr != NULL)` (or `if (ptr != nullptr)`).",
                fix_diff=None
            )

        # Buffer Overflow / fortify-source
        if "fortify-source" in lower_flag or "overflow" in lower_msg:
            return FindingCreate(
                rule_id="SEC-C-BUF-001",
                title="Unsafe Buffer Operation / Potential Overflow",
                description=(
                    f"Buffer overflow risk detected on line {line}: {clean_msg}. "
                    "Writing more data into a fixed-size buffer than it can accommodate overwrites adjacent stack or heap memory (CWE-120 / CWE-787)."
                ),
                severity="critical",
                category="security",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Use bounds-checked functions such as `snprintf()`, `strncpy()`, or dynamic containers (`std::string`).",
                fix_diff=None
            )

        # Use-After-Free (Clang SA cplusplus.NewDelete / unix.Malloc / use after it is freed)
        if "after it is freed" in lower_msg or "use-after-free" in lower_msg or "use of memory after" in lower_msg:
            uaf_rule_id = "SEC-C-UAF-001" if ("unix.malloc" in lower_flag or "free" in lower_msg) else "SEC-CPP-UAF-001"
            return FindingCreate(
                rule_id=uaf_rule_id,
                title="Use-After-Free Vulnerability (CWE-416)",
                description=(
                    f"Use-after-free memory corruption detected on line {line}: {clean_msg}. "
                    "Accessing or dereferencing heap memory after it has been deallocated invokes undefined behavior "
                    "and risks arbitrary code execution or heap corruption (CWE-416)."
                ),
                severity="critical",
                category="security",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Do not access or dereference pointers after calling delete or free. Set pointer to nullptr immediately after deallocation: `ptr = nullptr;`.",
                fix_diff=None
            )

        # Memory Leaks (C++ new/delete, unix.Malloc)
        if "newdeleteleaks" in lower_flag or "malloc" in lower_flag or "leak" in lower_msg:
            mem_rule_id = "BUG-C-MEM-001" if ("unix.malloc" in lower_flag or "malloc" in lower_flag) else "BUG-CPP-MEM-001"
            return FindingCreate(
                rule_id=mem_rule_id,
                title="Resource / Dynamic Memory Leak",
                description=(
                    f"Potential memory leak detected on line {line}: {clean_msg}. "
                    "Dynamically allocated heap memory is not properly freed before going out of scope (CWE-401)."
                ),
                severity="high",
                category="bug",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Ensure all allocated memory is paired with `free()` or `delete`, or utilize RAII smart pointers (`std::unique_ptr`).",
                fix_diff=None
            )

        # Uninitialized Variables
        if "uninitialized" in lower_flag or "uninitialized" in lower_msg:
            return FindingCreate(
                rule_id="BUG-C-UNINIT-001",
                title="Use of Uninitialized Variable",
                description=(
                    f"Variable used before initialization on line {line}: {clean_msg}. "
                    "Reading uninitialized memory yields indeterminate values and leads to undefined execution behavior (CWE-457)."
                ),
                severity="high",
                category="bug",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Initialize variable explicitly at the point of declaration (e.g., `int val = 0;`).",
                fix_diff=None
            )

        # Format String Security
        if "format-security" in lower_flag or "format not a string literal" in lower_msg:
            return FindingCreate(
                rule_id="SEC-C-FMT-001",
                title="Format String Vulnerability",
                description=(
                    f"Format string vulnerability on line {line}: {clean_msg}. "
                    "Passing dynamic user input directly as a format string allows attackers to read or write arbitrary memory (CWE-134)."
                ),
                severity="critical",
                category="security",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Always provide a constant format string literal: `printf(\"%s\", user_str);`.",
                fix_diff=None
            )

        # Deprecated Inherently Dangerous Functions (e.g. gets)
        if "deprecated-declarations" in lower_flag and "gets" in lower_msg:
            return FindingCreate(
                rule_id="SEC-C-BUF-002",
                title="Use of Inherently Dangerous Function (`gets`)",
                description=(
                    f"Use of deprecated dangerous function `gets` on line {line}: {clean_msg}. "
                    "The `gets` function cannot prevent buffer overflow and was removed from ISO C11 (CWE-242)."
                ),
                severity="critical",
                category="security",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Replace `gets(buf)` with `fgets(buf, sizeof(buf), stdin)`.",
                fix_diff=None
            )

        # Unused Variables / Dead Stores (Quality / Style)
        if "unused" in lower_flag or "deadstores" in lower_flag or "never read" in lower_msg:
            return FindingCreate(
                rule_id=f"ADV-C-UNUSED-{flag.upper()}" if flag else "ADV-C-UNUSED",
                title=f"Unused Code / Dead Store: {clean_msg[:60]}",
                description=f"Compiler detected an unused construct or dead store on line {line}: {clean_msg}.",
                severity="low",
                category="quality",
                source="static",
                line_start=line,
                line_end=line,
                column_start=col,
                column_end=col,
                evidence=evidence,
                confidence="high",
                suggested_fix="Remove the unused variable or incorporate it into the computation.",
                fix_diff=None
            )

        # Default Compiler Warning
        return FindingCreate(
            rule_id=f"CLANG-WARN-{flag.upper()}" if flag else "CLANG-WARN-GENERAL",
            title=f"Compiler Warning: {clean_msg[:70]}",
            description=f"Clang diagnostic issued on line {line}, col {col}: {clean_msg}.",
            severity="medium",
            category="quality",
            source="static",
            line_start=line,
            line_end=line,
            column_start=col,
            column_end=col,
            evidence=evidence,
            confidence="high",
            suggested_fix="Review and resolve the diagnostic per ISO standard guidelines.",
            fix_diff=None
        )
