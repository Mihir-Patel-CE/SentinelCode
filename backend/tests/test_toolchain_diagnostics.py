import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.services.analyzers.sandbox import CompilerSandbox
from app.services.analyzers.c_analyzer import CAnalyzer
from app.services.analyzers.cpp_analyzer import CppAnalyzer
from app.services.scoring import ScoringEngine


def test_compiler_sandbox_diagnostics_structure():
    diag_c = CompilerSandbox.get_toolchain_diagnostics("clang")
    assert "name" in diag_c
    assert "available" in diag_c
    assert "path" in diag_c
    assert "version" in diag_c
    assert diag_c["name"] == "clang"

    diag_cpp = CompilerSandbox.get_toolchain_diagnostics("clang++")
    assert "name" in diag_cpp
    assert "available" in diag_cpp
    assert "path" in diag_cpp
    assert "version" in diag_cpp
    assert diag_cpp["name"] == "clang++"


def test_compiler_version_format():
    # If clang is available in the test environment, ensure version string is non-empty
    if CompilerSandbox.resolve_executable("clang"):
        version = CompilerSandbox.get_compiler_version("clang")
        assert version is not None
        assert "clang" in version.lower()


def test_health_endpoint_includes_toolchains(client: TestClient):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "toolchains" in data
    assert "clang" in data["toolchains"]
    assert "clang++" in data["toolchains"]


def test_diagnostics_endpoint(client: TestClient):
    res = client.get("/api/v1/diagnostics")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "database" in data
    assert data["database"]["connected"] is True
    assert "toolchains" in data
    assert "c" in data["toolchains"]
    assert "cpp" in data["toolchains"]


def test_missing_compiler_returns_failed_status_and_no_false_success():
    """
    Verifies that when clang is missing from system PATH:
    1. Status is 'failed' (NOT 'completed')
    2. Does not report zero findings as a successful clean analysis
    3. Scores are None (no perfect 100 award)
    """
    with patch.object(CompilerSandbox, "is_available", return_value=False):
        c_analyzer = CAnalyzer()
        res = c_analyzer.analyze("int main(void) { return 0; }")

        assert res.status == "failed"
        assert "is not available in the system PATH" in res.error_message
        assert res.coverage_summary.startswith("Analyzer unavailable")

        # Scoring verification: failed status must NEVER award 100/100
        quality, security, maint = ScoringEngine.calculate(
            findings=res.findings,
            code="int main(void) { return 0; }",
            status=res.status
        )
        assert quality is None
        assert security is None
        assert maint is None


def test_cpp_missing_compiler_returns_failed_status():
    with patch.object(CompilerSandbox, "is_available", return_value=False):
        cpp_analyzer = CppAnalyzer()
        res = cpp_analyzer.analyze("int main() { return 0; }")

        assert res.status == "failed"
        assert "is not available in the system PATH" in res.error_message
        assert res.coverage_summary.startswith("Analyzer unavailable")

        quality, security, maint = ScoringEngine.calculate(
            findings=res.findings,
            code="int main() { return 0; }",
            status=res.status
        )
        assert quality is None
        assert security is None
        assert maint is None


def test_api_analyze_when_compiler_unavailable(client: TestClient):
    """
    End-to-end API test: when toolchain is simulated unavailable,
    the API returns a review with status='failed' and quality_score=None.
    """
    with patch.object(CompilerSandbox, "is_available", return_value=False):
        response = client.post(
            "/api/v1/reviews/analyze",
            json={
                "code": "#include <stdio.h>\nint main() { return 0; }",
                "language": "c",
                "enable_ai": False
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "failed"
        assert data["quality_score"] is None
        assert data["security_score"] is None
        assert "is not available in the system PATH" in data["summary"]
