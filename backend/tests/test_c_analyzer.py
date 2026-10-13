import pytest
import os
from unittest.mock import patch
from app.services.analyzers.c_analyzer import CAnalyzer
from app.services.analyzers.sandbox import CompilerSandbox, CompilerNotFoundError
from app.services.scoring import ScoringEngine


def test_valid_c_program_clean():
    """Valid, clean C program compiles without errors or false positives."""
    analyzer = CAnalyzer()
    code = """#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int sum = add(10, 20);
    printf("Sum is %d\\n", sum);
    return 0;
}
"""
    res = analyzer.analyze(code)
    assert res.status == "completed"
    # Filter out any non-error compiler warnings about system headers if any
    syntax_or_security_findings = [
        f for f in res.findings if f.category in ("syntax", "security", "bug")
    ]
    assert len(syntax_or_security_findings) == 0

    quality, security, maintainability = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is not None and quality >= 90
    assert security == 100


def test_c_syntax_error_not_labeled_critical_security():
    """Syntax error is categorized as syntax, NOT as a critical security vulnerability."""
    analyzer = CAnalyzer()
    code = """#include <stdio.h>
int main(void) {
    int x = 42
    return 0;
}
"""
    res = analyzer.analyze(code)
    assert res.status == "completed_with_limitations"
    syntax_findings = [f for f in res.findings if f.category == "syntax"]
    assert len(syntax_findings) > 0

    for sf in syntax_findings:
        assert sf.category == "syntax"
        assert sf.severity in ("high", "medium")
        assert sf.severity != "critical"
        assert sf.line_start is not None

    # Quality score should be penalized for syntax error, never 100
    quality, security, _ = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is not None
    assert quality < 90


def test_c_out_of_bounds_detection():
    """Array indexing past capacity is detected as bug/oob."""
    analyzer = CAnalyzer()
    code = """#include <stdio.h>
void test_oob(void) {
    int buffer[5];
    buffer[12] = 42;
}
"""
    res = analyzer.analyze(code)
    oob = next((f for f in res.findings if "OOB" in (f.rule_id or "") or "bounds" in (f.rule_id or "").lower() or "bounds" in f.title.lower()), None)
    assert oob is not None
    assert oob.category == "bug"
    assert oob.severity == "high"
    assert oob.line_start is not None


def test_c_unsafe_buffer_operations_gets_and_strcpy():
    """Dangerous buffer functions gets and strcpy are flagged as security vulnerabilities."""
    analyzer = CAnalyzer()
    code = """#include <stdio.h>
#include <string.h>

void read_and_copy(char *src) {
    char buf[16];
    gets(buf);
    strcpy(buf, src);
}
"""
    res = analyzer.analyze(code)
    rule_ids = [f.rule_id for f in res.findings]
    assert any("SEC-C-001" in rid or "SEC-C-BUF-002" in rid for rid in rule_ids)
    assert any("SEC-C-002" in rid or "BUF" in rid for rid in rule_ids)

    # gets must be critical security
    gets_finding = next((f for f in res.findings if "gets" in f.title.lower() or f.rule_id in ("SEC-C-001", "SEC-C-BUF-002")), None)
    assert gets_finding is not None
    assert gets_finding.category == "security"
    assert gets_finding.severity == "critical"


def test_c_format_string_vulnerability():
    """Direct variable format string in printf is flagged as critical format string vulnerability."""
    analyzer = CAnalyzer()
    code = """#include <stdio.h>
void log_message(const char *msg) {
    printf(msg);
}
"""
    res = analyzer.analyze(code)
    fmt = next((f for f in res.findings if "FMT" in (f.rule_id or "") or "format" in f.title.lower()), None)
    assert fmt is not None
    assert fmt.category == "security"
    assert fmt.severity == "critical"


def test_c_double_free_detection():
    """Double free on same pointer is detected."""
    analyzer = CAnalyzer()
    code = """#include <stdlib.h>
void cleanup(char *p) {
    free(p);
    free(p);
}
"""
    res = analyzer.analyze(code)
    df = next((f for f in res.findings if f.rule_id == "BUG-C-004" or "double free" in f.title.lower()), None)
    assert df is not None
    assert df.category == "security"
    assert df.severity == "critical"


def test_c_null_pointer_and_unchecked_malloc():
    """Unchecked malloc before dereference is flagged."""
    analyzer = CAnalyzer()
    code = """#include <stdlib.h>
void allocate_node(void) {
    int *data = (int *)malloc(sizeof(int) * 10);
    data[0] = 100;
}
"""
    res = analyzer.analyze(code)
    null_finding = next((f for f in res.findings if "NULL" in (f.rule_id or "") or "malloc" in f.title.lower()), None)
    assert null_finding is not None
    assert null_finding.category == "bug"


def test_c_compiler_unavailable_reports_configuration_error():
    """If compiler executable is unavailable, reports clear configuration error and status='failed'."""
    analyzer = CAnalyzer(compiler_cmd="nonexistent-clang-compiler-xyz")
    code = "int main(void) { return 0; }"
    res = analyzer.analyze(code)
    assert res.status == "failed"
    assert res.error_message is not None
    assert "Analyzer unavailable" in res.error_message or "not available" in res.error_message
    assert len(res.findings) == 0

    # Ensure ScoringEngine never produces perfect or valid scores on failed analysis
    quality, security, maintainability = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is None
    assert security is None
    assert maintainability is None


def test_compiler_sandbox_security_isolation():
    """CompilerSandbox isolates environment by stripping secrets and preventing code execution."""
    sandbox = CompilerSandbox(timeout_seconds=3.0)
    # Set a sensitive dummy environment variable on backend
    os.environ["SECRET_DATABASE_PASSWORD"] = "super-secret-production-password"

    # Verify that _build_isolated_env does NOT contain backend secrets
    clean_env = sandbox._build_isolated_env("/tmp/test_dir")
    assert "SECRET_DATABASE_PASSWORD" not in clean_env
    assert "PATH" in clean_env
    assert clean_env["TMPDIR"] == "/tmp/test_dir"
