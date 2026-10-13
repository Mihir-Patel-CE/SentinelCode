import re
from typing import List, Optional
from app.services.analyzers.base import BaseAnalyzer, AnalysisResult
from app.services.analyzers.sandbox import CompilerSandbox, CompilerNotFoundError
from app.services.analyzers.clang_parser import ClangDiagnosticParser
from app.schemas.review import FindingCreate
from app.core.logging import logger


CPP_STATIC_RULES = [
    {
        "id": "SEC-CPP-001",
        "regex": re.compile(r'\b(gets|strcpy|strcat|sprintf)\s*\('),
        "title": "Use of Unbounded Legacy C String Functions in C++ (CWE-120)",
        "description": (
            "Legacy C string functions like `strcpy` or `sprintf` do not enforce buffer boundaries and bypass C++ type safety. "
            "In modern C++, prefer `std::string`, `std::string_view`, or `std::format` / `snprintf`."
        ),
        "severity": "high",
        "category": "security",
        "fix": "Use `std::string` or bounds-checked string manipulation.",
        "diff": '- char buf[64]; strcpy(buf, input);\n+ std::string buf = input;'
    },
    {
        "id": "BUG-CPP-002",
        "regex": re.compile(r'new\s+[a-zA-Z0-9_]+\s*\[\s*[^\]]+\s*\][\s\S]{1,200}\bdelete\s+(?!\[\])[a-zA-Z0-9_]+\s*;'),
        "title": "Deallocation Mismatch: Array `new[]` Freed with Scalar `delete` (CWE-762)",
        "description": (
            "Memory allocated with array `new[]` must be deallocated using `delete[]`. "
            "Invoking scalar `delete` invokes undefined behavior and typically leaks array destructors and heap headers (CWE-762)."
        ),
        "severity": "high",
        "category": "bug",
        "fix": "Use `delete[] ptr;` to release array allocations, or replace raw arrays with `std::vector`.",
        "diff": "- delete ptr;\n+ delete[] ptr;"
    },
    {
        "id": "BUG-CPP-003",
        "regex": re.compile(r'([a-zA-Z0-9_]+&\s*|const\s+[a-zA-Z0-9_]+&\s*|[a-zA-Z0-9_]+\*\s*)[a-zA-Z0-9_]+\s*\([^)]*\)\s*\{[\s\S]*?\breturn\s+&?([a-zA-Z_][a-zA-Z0-9_]*)\s*;'),
        "title": "Dangling Reference / Pointer to Local Stack Object (CWE-562)",
        "description": (
            "Returning a reference or pointer to a stack-allocated local variable results in a dangling reference. "
            "The memory is invalidated as soon as the function frame pops, leading to memory corruption or crashes (CWE-562)."
        ),
        "severity": "critical",
        "category": "bug",
        "fix": "Return the object by value (leveraging Move Semantics / RVO) or allocate it with `std::unique_ptr`.",
        "diff": "- const std::string& getName() { std::string s = \"test\"; return s; }\n+ std::string getName() { std::string s = \"test\"; return s; }"
    },
    {
        "id": "BUG-CPP-004",
        "regex": re.compile(r'class\s+([a-zA-Z0-9_]+)[\s\S]*?virtual\s+[a-zA-Z0-9_<>*&\s]+\s+[a-zA-Z0-9_]+\s*\([^)]*\)[\s\S]*?~(?!\1\(\)\s*=\s*default|\1\(\)\s*\{)\1'),
        "title": "Polymorphic Base Class Missing Virtual Destructor (CWE-1079)",
        "description": (
            "A base class containing `virtual` methods that lacks a `virtual` destructor causes undefined behavior "
            "when derived objects are deleted via base class pointers, leaking derived resources (CWE-1079)."
        ),
        "severity": "medium",
        "category": "bug",
        "fix": "Declare the destructor virtual: `virtual ~ClassName() = default;`.",
        "diff": "- ~Base() {}\n+ virtual ~Base() = default;"
    },
    {
        "id": "BUG-CPP-005",
        "regex": re.compile(r'\bcatch\s*\(\s*(std::exception|std::runtime_error|std::logic_error|[A-Z][a-zA-Z0-9_]*Exception)\s+([a-zA-Z0-9_]+)\s*\)'),
        "title": "Exception Caught by Value Causing Object Slicing",
        "description": (
            "Catching exceptions by value slices derived exception attributes and creates unnecessary object copies. "
            "Always catch polymorphic exceptions by `const` reference."
        ),
        "severity": "low",
        "category": "quality",
        "fix": "Catch exception by const reference: `catch (const std::exception& e)`.",
        "diff": "- catch (std::exception e)\n+ catch (const std::exception& e)"
    },
    {
        "id": "BUG-CPP-006",
        "regex": re.compile(r'([a-zA-Z0-9_]+)\.lock\s*\(\s*\);(?!(?:[\s\S]{1,120}(?:std::lock_guard|std::unique_lock)))'),
        "title": "Manual Mutex Locking without RAII Guard (Deadlock Risk, CWE-833)",
        "description": (
            "Calling `.lock()` directly on a mutex without an RAII wrapper (`std::lock_guard` or `std::unique_lock`) "
            "causes severe deadlock if an early return, break, or unexpected exception occurs prior to `.unlock()` (CWE-833)."
        ),
        "severity": "high",
        "category": "bug",
        "fix": "Use RAII lock management: `std::lock_guard<std::mutex> lock(mtx);`.",
        "diff": "- mtx.lock();\n- /* work */\n- mtx.unlock();\n+ std::lock_guard<std::mutex> lock(mtx);\n+ /* work */"
    },
    {
        "id": "SEC-CPP-002",
        "regex": re.compile(r'(?i)(password|secret|api_key|token|private_key)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']'),
        "title": "Hardcoded Credential or API Token in C++ Source (CWE-798)",
        "description": (
            "Hardcoding credentials or API keys directly in C++ code embeds plaintext secrets inside compiled binaries (CWE-798)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Read credentials from environment variables using `std::getenv()` or secure key stores.",
        "diff": '- const std::string token = "prod_secret_12345";\n+ const char* env_token = std::getenv("API_TOKEN");'
    },
    {
        "id": "BUG-CPP-007",
        "regex": re.compile(r'\bdelete\s+(?:\[\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*;[\s\S]{1,120}\bdelete\s+(?:\[\]\s*)?\1\s*;'),
        "title": "Double Delete Vulnerability (CWE-415)",
        "description": (
            "Calling `delete` twice on the same pointer without reallocating triggers undefined behavior, "
            "heap corruption, and potential arbitrary code execution (CWE-415)."
        ),
        "severity": "critical",
        "category": "security",
        "fix": "Set pointer to `nullptr` immediately after calling delete: `delete ptr; ptr = nullptr;`.",
        "diff": "- delete ptr;\n- delete ptr;\n+ delete ptr;\n+ ptr = nullptr;"
    }
]


class CppAnalyzer(BaseAnalyzer):
    """
    Production-grade C++ static analyzer utilizing Clang++ compiler diagnostics (-fsyntax-only),
    Clang Static Analysis (--analyze), modern RAII resource auditing, and security inspection.
    """

    def __init__(self, compiler_cmd: str = "clang++", timeout: float = 5.0):
        self._compiler_cmd = compiler_cmd
        self._sandbox = CompilerSandbox(timeout_seconds=timeout)

    @property
    def language(self) -> str:
        return "cpp"

    @property
    def name(self) -> str:
        return "C++ Clang++ Compiler Diagnostic & Static Security Analyzer"

    @property
    def features(self) -> List[str]:
        return [
            "Clang++ -fsyntax-only Modern C++ Syntax Verification (C++17/C++20)",
            "Clang++ Static Analyzer New/Delete Resource Leaks (cplusplus.NewDeleteLeaks)",
            "Array and Container Out-of-Bounds Detection (-Warray-bounds)",
            "Use-After-Free Memory Safety Inspection (CWE-416)",
            "Array new[] vs delete Mismatch Audit (CWE-762)",
            "Dangling Reference / Local Stack Object Return Audit (CWE-562)",
            "Polymorphic Virtual Destructor Check (CWE-1079)",
            "Exception Slicing Inspection (Catch by Value vs const&)",
            "Mutex RAII Lock Safety Audit (CWE-833)",
            "Unsafe Legacy C String Usage Inspection (CWE-120)",
            "Hardcoded Credential & Token Inspection (CWE-798)",
            "Sandboxed Compilation Isolation with Resource Limits"
        ]

    @property
    def limitations(self) -> str:
        return (
            "Analyzes single-file C++ units without multi-translation unit linker resolution. "
            "External third-party C++ libraries (Boost, Qt) must have headers available or mocked inline."
        )

    def analyze(self, code: str) -> AnalysisResult:
        # Check if compiler is available in the deployment environment
        if not self._sandbox.is_available(self._compiler_cmd):
            return AnalysisResult(
                status="failed",
                language="cpp",
                findings=[],
                coverage_summary="Analyzer unavailable: C++ Compiler toolchain is unavailable in this environment.",
                limitations=self.limitations,
                error_message=(
                    f"Analyzer unavailable: Clang++ compiler/analyzer executable '{self._compiler_cmd}' is not available "
                    "in the system PATH. Please verify LLVM/Clang installation."
                )
            )

        findings: List[FindingCreate] = []
        has_syntax_errors = False

        # Pass 1: Syntax & compiler warnings via Clang++
        try:
            res_syntax = self._sandbox.execute_in_sandbox(
                executable_name=self._compiler_cmd,
                arguments=[
                    "-fsyntax-only",
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Warray-bounds",
                    "-Wnull-dereference",
                    "-Wuninitialized",
                    "-Wformat=2",
                    "-Wdeprecated-declarations",
                    "-x", "c++",
                    "{INPUT_FILE}"
                ],
                code=code,
                filename="snippet.cpp"
            )
            if res_syntax.timed_out:
                return AnalysisResult(
                    status="failed",
                    language="cpp",
                    findings=[],
                    coverage_summary="Analysis failed: C++ Compiler execution timed out.",
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
                language="cpp",
                findings=[],
                coverage_summary="Analysis failed: Compiler toolchain not found.",
                error_message=str(e)
            )
        except Exception as e:
            logger.error(f"Error during C++ syntax analysis pass: {e}")

        # Pass 2: Clang Static Analyzer pass (if no fatal syntax errors)
        if not has_syntax_errors:
            try:
                res_sa = self._sandbox.execute_in_sandbox(
                    executable_name=self._compiler_cmd,
                    arguments=[
                        "--analyze",
                        "-Xanalyzer",
                        "-analyzer-output=text",
                        "-std=c++17",
                        "-x", "c++",
                        "{INPUT_FILE}"
                    ],
                    code=code,
                    filename="snippet.cpp"
                )
                if not res_sa.timed_out:
                    sa_findings = ClangDiagnosticParser.parse(res_sa.stderr, code)
                    findings.extend(sa_findings)
            except Exception as e:
                logger.debug(f"Clang++ --analyze pass skipped or encountered error: {e}")

        # Pass 3: Complementary C++ Static Analysis Rules
        code_lines = code.splitlines()
        for rule in CPP_STATIC_RULES:
            pattern: re.Pattern = rule["regex"]
            # Check multiline matches for rules that span blocks
            if rule["id"] in ("BUG-CPP-002", "BUG-CPP-003", "BUG-CPP-004", "BUG-CPP-007"):
                match = pattern.search(code)
                if match:
                    start_pos = match.start()
                    line_no = code[:start_pos].count("\n") + 1
                    col_start = start_pos - code.rfind("\n", 0, start_pos)
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

        # Check for unmanaged raw `new` without `delete` or smart pointer
        new_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+([a-zA-Z0-9_]+)')
        for idx, line in enumerate(code_lines, start=1):
            m = new_pattern.search(line)
            if m:
                var_name = m.group(1)
                # Check entire code for delete var_name
                if not re.search(rf'\bdelete(\[\])?\s+{var_name}\b', code) and "unique_ptr" not in line and "shared_ptr" not in line:
                    findings.append(FindingCreate(
                        rule_id="BUG-CPP-MEM-001",
                        title=f"Unmanaged Raw Allocation / Potential Memory Leak on `{var_name}` (CWE-401)",
                        description=(
                            f"`{var_name}` is allocated via `new` on line {idx} without a corresponding `delete`. "
                            "In modern C++, utilize `std::make_unique` or `std::make_shared` to guarantee automatic RAII cleanup (CWE-401)."
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
                        suggested_fix=f"Replace raw pointer with smart pointer: `auto {var_name} = std::make_unique<{m.group(2)}>(...);`",
                        fix_diff=f"- {var_name} = new {m.group(2)}();\n+ auto {var_name} = std::make_unique<{m.group(2)}>();"
                    ))

        # Check for static array bound violations: e.g. int arr[3]; arr[5] = 10;
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
                            rule_id="BUG-CPP-OOB-001",
                            title=f"Static Array Bound Violation on `{arr_name}` (CWE-119)",
                            description=(
                                f"Array `{arr_name}` has size {size}, but is indexed at {idx_val} on line {idx}. "
                                "This creates out-of-bounds access causing undefined behavior or memory corruption (CWE-119 / CWE-787)."
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
                            suggested_fix=f"Keep index strictly within 0 and {size - 1}."
                        ))

        # Check for Use-After-Free: delete ptr; followed by *ptr or ptr-> or ptr[...]
        delete_re = re.compile(r'\bdelete\s+(?:\[\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*;')
        for idx, line in enumerate(code_lines, start=1):
            for dm in delete_re.finditer(line):
                del_var = dm.group(1)
                # Look in subsequent lines for use of del_var (e.g. *del_var, del_var->, del_var[)
                for follow_idx in range(idx, min(len(code_lines), idx + 20)):
                    follow_line = code_lines[follow_idx]
                    # If reallocated or reassigned, stop searching
                    if re.search(rf'(?<!\*)\b{del_var}\s*=\s*', follow_line):
                        break
                    uaf_match = re.search(rf'(\*\s*{del_var}\b|{del_var}\s*->|{del_var}\s*\[)', follow_line)
                    if uaf_match:
                        findings.append(FindingCreate(
                            rule_id="SEC-CPP-UAF-001",
                            title=f"Use-After-Free Vulnerability on `{del_var}` (CWE-416)",
                            description=(
                                f"Pointer `{del_var}` was deallocated via delete on line {idx}, but accessed or dereferenced "
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
                            suggested_fix=f"Do not access `{del_var}` after calling delete. Set `{del_var} = nullptr;` immediately.",
                            fix_diff=f"- delete {del_var};\n+ delete {del_var};\n+ {del_var} = nullptr;"
                        ))
                        break

        # Deduplicate findings by rule_id and line
        deduped: List[FindingCreate] = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_start)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        status = "completed_with_limitations" if has_syntax_errors else "completed"
        coverage_summary = (
            f"Clang++ compiler verification completed with syntax limitations ({len(deduped)} findings)."
            if has_syntax_errors
            else f"Clang++ compiler diagnostics & C++ RAII security analysis completed ({len(deduped)} findings)."
        )

        return AnalysisResult(
            status=status,
            language="cpp",
            findings=deduped,
            coverage_summary=coverage_summary,
            limitations=self.limitations
        )
