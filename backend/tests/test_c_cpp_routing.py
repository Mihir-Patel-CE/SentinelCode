import pytest
from unittest.mock import patch
from app.services.analyzers.registry import registry
from app.services.analyzers.c_analyzer import CAnalyzer
from app.services.analyzers.cpp_analyzer import CppAnalyzer
from app.services.analyzers.python_ast import PythonAnalyzer
from app.schemas.review import ReviewCreateRequest
from app.services.review_service import review_service


C_SAMPLE_CODE = """#include <stdio.h>
#include <string.h>

void handle(const char *input) {
    char buf[16];
    strcpy(buf, input);
}

int main(void) {
    handle("test");
    return 0;
}
"""

CPP_SAMPLE_CODE = """#include <iostream>
#include <vector>
#include <memory>

class Service {
public:
    void run() {
        std::cout << "Service running" << std::endl;
    }
};

int main() {
    auto svc = std::make_unique<Service>();
    svc->run();
    return 0;
}
"""

PYTHON_SAMPLE_CODE = """def greet(name: str) -> str:
    return f"Hello, {name}"
"""


def test_registry_retrieves_c_and_cpp_analyzers():
    """Verify registry resolves c, cpp, c++, and cxx identifiers correctly."""
    c_analyzer = registry.get("c")
    assert isinstance(c_analyzer, CAnalyzer)

    cpp_analyzer = registry.get("cpp")
    assert isinstance(cpp_analyzer, CppAnalyzer)

    cpp_alias = registry.get("c++")
    assert isinstance(cpp_alias, CppAnalyzer)

    cxx_alias = registry.get("cxx")
    assert isinstance(cxx_alias, CppAnalyzer)


def test_automatic_language_detection_c():
    """C code with #include <stdio.h> or strcpy routes to 'c', never 'python'."""
    detected = registry.detect_language(C_SAMPLE_CODE)
    assert detected == "c"
    assert detected != "python"


def test_automatic_language_detection_cpp():
    """C++ code with #include <iostream> or std:: routes to 'cpp', never 'python'."""
    detected = registry.detect_language(CPP_SAMPLE_CODE)
    assert detected == "cpp"
    assert detected != "python"


def test_automatic_language_detection_python_preserved():
    """Python code is still accurately identified as 'python'."""
    detected = registry.detect_language(PYTHON_SAMPLE_CODE)
    assert detected == "python"


@pytest.mark.asyncio
async def test_c_code_never_sent_to_python_parser(db_session):
    """C code submission routes to CAnalyzer and never touches PythonAnalyzer."""
    with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser was called for C code!")) as mock_py:
        req = ReviewCreateRequest(
            title="C Routing Regression Check",
            language="c",
            code=C_SAMPLE_CODE,
            enable_ai=False
        )
        review = await review_service.execute_review(db_session, req)
        assert review.language == "c"
        assert review.status == "completed"
        assert mock_py.call_count == 0


@pytest.mark.asyncio
async def test_cpp_code_never_sent_to_python_parser(db_session):
    """C++ code submission routes to CppAnalyzer and never touches PythonAnalyzer."""
    with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser was called for C++ code!")) as mock_py:
        req = ReviewCreateRequest(
            title="C++ Routing Regression Check",
            language="cpp",
            code=CPP_SAMPLE_CODE,
            enable_ai=False
        )
        review = await review_service.execute_review(db_session, req)
        assert review.language == "cpp"
        assert review.status == "completed"
        assert mock_py.call_count == 0


@pytest.mark.asyncio
async def test_auto_detect_c_routes_correctly(db_session):
    """Auto-detected C code routes to CAnalyzer and never touches PythonAnalyzer."""
    with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser was called for auto C code!")) as mock_py:
        req = ReviewCreateRequest(
            title="Auto C Routing Check",
            language="auto",
            code=C_SAMPLE_CODE,
            enable_ai=False
        )
        review = await review_service.execute_review(db_session, req)
        assert review.language == "c"
        assert mock_py.call_count == 0


@pytest.mark.asyncio
async def test_auto_detect_cpp_routes_correctly(db_session):
    """Auto-detected C++ code routes to CppAnalyzer and never touches PythonAnalyzer."""
    with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser was called for auto C++ code!")) as mock_py:
        req = ReviewCreateRequest(
            title="Auto C++ Routing Check",
            language="auto",
            code=CPP_SAMPLE_CODE,
            enable_ai=False
        )
        review = await review_service.execute_review(db_session, req)
        assert review.language == "cpp"
        assert mock_py.call_count == 0


def test_supported_languages_matrix_includes_c_and_cpp():
    """Verify capabilities matrix includes 'c' and 'cpp' as supported."""
    caps = registry.get_supported_languages()
    c_cap = next((c for c in caps if c.id == "c"), None)
    cpp_cap = next((c for c in caps if c.id == "cpp"), None)

    assert c_cap is not None
    assert c_cap.status == "supported"
    assert len(c_cap.features) > 0

    assert cpp_cap is not None
    assert cpp_cap.status == "supported"
    assert len(cpp_cap.features) > 0


def test_api_languages_endpoint_returns_c_and_cpp(client):
    """GET /api/v1/languages/ returns C and C++ capabilities."""
    response = client.get("/api/v1/languages/")
    assert response.status_code == 200
    langs = response.json()
    lang_ids = [l["id"] for l in langs]
    assert "c" in lang_ids
    assert "cpp" in lang_ids


def test_api_samples_endpoint_returns_c_and_cpp(client):
    """GET /api/v1/samples/ returns fixtures for C and C++."""
    response = client.get("/api/v1/samples/")
    assert response.status_code == 200
    samples = response.json()
    sample_langs = [s["language"] for s in samples]
    assert "c" in sample_langs
    assert "cpp" in sample_langs


def test_api_submit_c_review(client):
    """POST /api/v1/reviews/analyze with language='c' performs real C audit."""
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "C End-to-End API Test",
        "language": "c",
        "code": C_SAMPLE_CODE,
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["language"] == "c"
    assert data["status"] == "completed"
    assert len(data["findings"]) > 0
    assert any("strcpy" in f["description"].lower() or "buf" in f["rule_id"].lower() for f in data["findings"])


def test_api_submit_cpp_review(client):
    """POST /api/v1/reviews/analyze with language='cpp' performs real C++ audit."""
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "C++ End-to-End API Test",
        "language": "cpp",
        "code": CPP_SAMPLE_CODE,
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["language"] == "cpp"
    assert data["status"] == "completed"


@pytest.mark.asyncio
async def test_valid_cpp_never_reported_as_python_syntax_error(db_session):
    """Auto-detected C++ code is never misidentified as Python or reported with Python syntax errors."""
    cpp_source = """#include <iostream>
using namespace std;

class Calculator {
public:
    int multiply(int a, int b) {
        return a * b;
    }
};

int main() {
    Calculator calc;
    cout << "Product: " << calc.multiply(6, 7) << endl;
    return 0;
}
"""
    with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser called for C++!")) as mock_py:
        req = ReviewCreateRequest(
            title="Auto C++ Syntax Integrity",
            language="auto",
            code=cpp_source,
            enable_ai=False
        )
        review = await review_service.execute_review(db_session, req)
        assert review.language == "cpp"
        assert review.status == "completed"
        assert mock_py.call_count == 0
        # Verify no Python syntax error finding exists
        py_syntax_findings = [f for f in review.findings if f.rule_id == "SYN-PY-001" or "python" in f.title.lower()]
        assert len(py_syntax_findings) == 0


@pytest.mark.asyncio
async def test_cpp_defects_detection_oob_leak_uaf(db_session):
    """Detect and report out-of-bounds access, memory leaks, and use-after-free in C++ code."""
    vulnerable_cpp = """#include <iostream>

void inspect_defects() {
    // 1. Out-of-bounds access
    int numbers[4];
    numbers[10] = 55;

    // 2. Memory leak (unmanaged new)
    int *leaked_buffer = new int(100);

    // 3. Use-after-free
    int *target = new int(42);
    delete target;
    *target = 99;
}

int main() {
    inspect_defects();
    return 0;
}
"""
    req = ReviewCreateRequest(
        title="C++ Defects Comprehensive Audit",
        language="cpp",
        code=vulnerable_cpp,
        enable_ai=False
    )
    review = await review_service.execute_review(db_session, req)
    assert review.language == "cpp"
    rule_ids = [f.rule_id for f in review.findings]
    descriptions = [f.description.lower() for f in review.findings]
    titles = [f.title.lower() for f in review.findings]

    # Verify out-of-bounds access detected
    assert any("OOB" in rid or "array-bounds" in rid.lower() or "bounds" in t for rid, t in zip(rule_ids, titles))

    # Verify memory leak detected
    assert any("MEM" in rid or "leak" in d or "leak" in t for rid, d, t in zip(rule_ids, descriptions, titles))

    # Verify use-after-free detected
    assert any("UAF" in rid or "after-free" in t or "after it is freed" in d or "use-after-free" in t for rid, d, t in zip(rule_ids, descriptions, titles))


@pytest.mark.asyncio
async def test_explicit_language_selection_precedence(db_session):
    """Explicit language selection takes precedence over automatic detection."""
    # Source without header or standard keywords
    code = "int x = 42;"
    req_cpp = ReviewCreateRequest(
        title="Explicit C++",
        language="cpp",
        code=code,
        enable_ai=False
    )
    review_cpp = await review_service.execute_review(db_session, req_cpp)
    assert review_cpp.language == "cpp"

    py_code = "x = 42"
    req_py = ReviewCreateRequest(
        title="Explicit Python",
        language="python",
        code=py_code,
        enable_ai=False
    )
    review_py = await review_service.execute_review(db_session, req_py)
    assert review_py.language == "python"


@pytest.mark.asyncio
async def test_cpp_tooling_unavailable_returns_analyzer_unavailable_never_runs_python(db_session):
    """If C++ compiler is unavailable, returns 'Analyzer unavailable' and never runs Python analyzer."""
    cpp_analyzer = registry.get("cpp")
    with patch.object(cpp_analyzer._sandbox, "is_available", return_value=False):
        with patch.object(PythonAnalyzer, "analyze", side_effect=AssertionError("Python parser called!")) as mock_py:
            req = ReviewCreateRequest(
                title="Unavailable C++ Tooling",
                language="cpp",
                code="#include <iostream>\nint main() { return 0; }",
                enable_ai=False
            )
            review = await review_service.execute_review(db_session, req)
            assert review.status == "failed"
            assert "Analyzer unavailable" in (review.summary or "")
            assert mock_py.call_count == 0
            # Ensure scores are None, never perfect 100/100
            assert review.quality_score is None
            assert review.security_score is None
            assert review.maintainability_index is None


