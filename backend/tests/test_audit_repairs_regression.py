import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.services.analyzers.registry import registry
from app.services.analyzers.c_analyzer import CAnalyzer
from app.services.analyzers.cpp_analyzer import CppAnalyzer
from app.services.analyzers.python_ast import PythonAnalyzer
from app.services.analyzers.java import JavaAnalyzer
from app.services.analyzers.javascript import JavaScriptAnalyzer
from app.services.analyzers.sandbox import ExecutionResult
from app.services.scoring import ScoringEngine
from app.schemas.review import ReviewCreateRequest
from app.services.review_service import review_service


# 1. Valid code in every supported language (C, C++, Python, Java, JS, TS)
CLEAN_SNIPPETS = {
    "c": """#include <stdio.h>
int main(void) {
    printf("Clean C code\\n");
    return 0;
}
""",
    "cpp": """#include <iostream>
#include <memory>
int main() {
    auto ptr = std::make_unique<int>(10);
    std::cout << *ptr << std::endl;
    return 0;
}
""",
    "python": """def clean_sum(items: list[int]) -> int:
    total = 0
    for item in items:
        total += item
    return total
""",
    "java": """public class CleanApp {
    public static void main(String[] args) {
        System.out.println("Clean Java code");
    }
}
""",
    "javascript": """function calculateArea(width, height) {
    if (width <= 0 || height <= 0) return 0;
    return width * height;
}
""",
    "typescript": """interface Point {
    x: number;
    y: number;
}
function getDistance(p: Point): number {
    return Math.hypot(p.x, p.y);
}
"""
}


@pytest.mark.parametrize("lang,code", list(CLEAN_SNIPPETS.items()))
def test_valid_code_all_languages_completed_clean(lang: str, code: str):
    analyzer = registry.get(lang)
    assert analyzer is not None
    res = analyzer.analyze(code)
    assert res.status == "completed"
    assert len(res.findings) == 0

    quality, security, maintainability = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is not None and quality >= 90
    assert security == 100
    assert maintainability is not None and maintainability >= 80


# 2. Representative syntax errors in supported languages
def test_syntax_errors_categorized_accurately():
    # Python syntax error
    py_res = PythonAnalyzer().analyze("def bad_syntax(:")
    assert py_res.status == "completed_with_limitations"
    py_syntax = [f for f in py_res.findings if f.category == "syntax"]
    assert len(py_syntax) > 0
    assert py_syntax[0].severity in ("high", "medium")

    # Java syntax error
    jv_res = JavaAnalyzer().analyze("public class Broken { int x = (1 + 2; }")
    assert jv_res.status == "completed_with_limitations"
    assert any(f.category == "syntax" for f in jv_res.findings)

    # JS syntax error
    js_res = JavaScriptAnalyzer(is_typescript=False).analyze("function test() { const x = [1, 2; }")
    assert js_res.status == "completed_with_limitations"
    assert any(f.category == "syntax" for f in js_res.findings)


# 3. Python Undefined Names & Scope Integrity
def test_python_undefined_name_detected():
    res = PythonAnalyzer().analyze("print(unassigned_variable_xyz)")
    undef = [f for f in res.findings if f.rule_id == "BUG-PY-004"]
    assert len(undef) == 1
    assert undef[0].severity == "high"
    assert undef[0].category == "bug"


def test_python_scopes_no_false_positive_undefined_names():
    code = """import os

def process_data(items):
    # Comprehensions
    squares = [x * x for x in items]
    evens = {x for x in items if x % 2 == 0}
    mapping = {str(k): k for k in items}
    gen = (y for y in items)

    # Lambda
    mapper = lambda val: val * 2

    # With statement
    with open('test.txt') as file_handle:
        content = file_handle.read()

    # Try / Except with named exception
    try:
        val = int('123')
    except ValueError as parse_err:
        print(parse_err)

    # Module / function level for loop
    for item in items:
        print(item)

    return squares, evens, mapping, gen, mapper(5)
"""
    res = PythonAnalyzer().analyze(code)
    undef = [f for f in res.findings if f.rule_id == "BUG-PY-004"]
    assert len(undef) == 0, f"Unexpected undefined name findings: {[f.title for f in undef]}"


# 4. C & C++ Memory Safety Detection
def test_c_memory_safety_uaf_and_leak():
    analyzer = CAnalyzer()
    c_code = """#include <stdlib.h>

void test_memory(void) {
    // 1. Unchecked calloc
    int *nums = (int *)calloc(10, sizeof(int));
    nums[0] = 5;

    // 2. Use-after-free
    char *ptr = (char *)malloc(32);
    free(ptr);
    *ptr = 'A';

    // 3. Potential memory leak (leaked_data never freed)
    int *leaked_data = (int *)malloc(64);
}
"""
    res = analyzer.analyze(c_code)
    rule_ids = {f.rule_id for f in res.findings}
    assert "SEC-C-UAF-001" in rule_ids
    assert "BUG-C-MEM-001" in rule_ids
    assert "BUG-C-NULL-002" in rule_ids

    # Verify column numbers are accurately populated
    uaf_finding = next(f for f in res.findings if f.rule_id == "SEC-C-UAF-001")
    assert uaf_finding.line_start is not None
    assert uaf_finding.column_start is not None and uaf_finding.column_start > 0


def test_cpp_double_delete_detection():
    analyzer = CppAnalyzer()
    cpp_code = """void double_cleanup(int *ptr) {
    delete ptr;
    delete ptr;
}
"""
    res = analyzer.analyze(cpp_code)
    assert any(f.rule_id == "BUG-CPP-007" for f in res.findings)
    dd_finding = next(f for f in res.findings if f.rule_id == "BUG-CPP-007")
    assert dd_finding.severity == "critical"
    assert dd_finding.category == "security"


# 5. Java Enhancements (Resource Leaks, Command Injection, Array Bounds, Null Deref)
def test_java_extended_vulnerability_detection():
    analyzer = JavaAnalyzer()
    java_code = """import java.io.*;

public class SecService {
    void doWork(String input) {
        // 1. Command Injection
        Runtime.getRuntime().exec("sh -c " + input);

        // 2. Resource leak
        BufferedReader reader = new BufferedReader(new FileReader("data.txt"));

        // 3. Array bounds
        int[] arr = new int[3];
        arr[5] = 10;

        // 4. Null deref
        String str = null;
        int len = str.length();
    }
}
"""
    res = analyzer.analyze(java_code)
    rule_ids = {f.rule_id for f in res.findings}
    assert "SEC-JV-005" in rule_ids
    assert "BUG-JV-RES-001" in rule_ids
    assert "BUG-JV-OOB-001" in rule_ids
    assert "BUG-JV-NULL-001" in rule_ids


# 6. JavaScript & TypeScript Enhancements
def test_javascript_and_typescript_rules():
    js_analyzer = JavaScriptAnalyzer(is_typescript=False)
    js_code = """function loadUser() {
    fetch('/api/user')
        .then(res => res.json());

    const elem = document.getElementById('username').value;
}
"""
    res_js = js_analyzer.analyze(js_code)
    rule_ids_js = {f.rule_id for f in res_js.findings}
    assert "BUG-JS-005" in rule_ids_js
    assert "BUG-JS-006" in rule_ids_js

    ts_analyzer = JavaScriptAnalyzer(is_typescript=True)
    ts_code = """// @ts-ignore
const x: any = 42;
"""
    res_ts = ts_analyzer.analyze(ts_code)
    rule_ids_ts = {f.rule_id for f in res_ts.findings}
    assert "TS-QUAL-001" in rule_ids_ts
    assert "TS-QUAL-002" in rule_ids_ts


# 7. Analyzer Executable Unavailable & Timeout
def test_analyzer_timeout_fails_safely():
    analyzer = CAnalyzer()
    timed_out_result = ExecutionResult(stdout="", stderr="Timeout", returncode=-1, timed_out=True)
    with patch.object(analyzer._sandbox, "execute_in_sandbox", return_value=timed_out_result):
        res = analyzer.analyze("int main(void) { return 0; }")
        assert res.status == "failed"
        assert "timed out" in (res.error_message or "").lower()

        # Score must be None
        q, s, m = ScoringEngine.calculate(res.findings, "int main(void) { return 0; }", res.status)
        assert q is None and s is None and m is None


# 8. Language Routing Precision
def test_language_routing_end_to_end():
    # C code with printf and malloc
    c_snippet = "#include <stdio.h>\nint main(void) { printf(\"hello\"); return 0; }"
    assert registry.detect_language(c_snippet) == "c"

    # C++ code with std::cout and iostream
    cpp_snippet = "#include <iostream>\nint main() { std::cout << 42 << std::endl; return 0; }"
    assert registry.detect_language(cpp_snippet) == "cpp"

    # Java class
    java_snippet = "package com.example;\npublic class Controller {\n    public static void main(String[] args) {}\n}"
    assert registry.detect_language(java_snippet) == "java"

    # Python
    py_snippet = "def calculate_tax(income):\n    return income * 0.2"
    assert registry.detect_language(py_snippet) == "python"

    # TypeScript
    ts_snippet = "interface ApiResponse<T> {\n    data: T;\n    status: number;\n}"
    assert registry.detect_language(ts_snippet) == "typescript"

    # JavaScript
    js_snippet = "const compute = (a, b) => {\n    console.log(a, b);\n    return a + b;\n};"
    assert registry.detect_language(js_snippet) == "javascript"


# 9. API End-to-End: Unsupported Language & Empty Code
def test_api_unsupported_language_and_empty_code(client: TestClient):
    # Empty code rejected
    res_empty = client.post("/api/v1/reviews/analyze", json={
        "title": "Empty snippet",
        "language": "python",
        "code": "   ",
        "enable_ai": False
    })
    assert res_empty.status_code == 422

    # Unsupported language
    res_unsupported = client.post("/api/v1/reviews/analyze", json={
        "title": "Ruby code",
        "language": "ruby",
        "code": "puts 'Hello Ruby'",
        "enable_ai": False
    })
    assert res_unsupported.status_code == 201
    data = res_unsupported.json()
    assert data["status"] == "unsupported_language"
    assert data["quality_score"] is None
    assert data["security_score"] is None
