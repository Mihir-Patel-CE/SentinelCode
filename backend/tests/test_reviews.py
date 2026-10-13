from fastapi.testclient import TestClient


def test_analyze_python_vulnerable_code(client: TestClient):
    payload = {
        "title": "SQL Injection Test",
        "language": "python",
        "code": """def fetch_user(db, user_id):\n    cursor = db.cursor()\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    return cursor.fetchone()""",
        "enable_ai": True
    }
    response = client.post("/api/v1/reviews/analyze", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["language"] == "python"
    assert data["quality_score"] < 100
    assert data["security_score"] < 100
    assert len(data["findings"]) > 0

    # Ensure findings tag sources properly
    sources = {f["source"] for f in data["findings"]}
    assert "static" in sources


def test_analyze_clean_code(client: TestClient):
    payload = {
        "title": "Clean Math Utility",
        "language": "python",
        "code": "def add_numbers(a: int, b: int) -> int:\n    return a + b",
        "enable_ai": True
    }
    response = client.post("/api/v1/reviews/analyze", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["quality_score"] == 100
    assert data["security_score"] == 100
    assert len(data["findings"]) == 0


def test_list_reviews_and_pagination(client: TestClient):
    for i in range(3):
        client.post("/api/v1/reviews/analyze", json={
            "title": f"Review {i}",
            "language": "python",
            "code": f"def func_{i}(): return {i}",
            "enable_ai": False
        })

    response = client.get("/api/v1/reviews/?page=1&size=2")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2
    assert data["total"] >= 3
    assert data["page"] == 1


def test_reject_empty_or_whitespace_code(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Empty snippet",
        "language": "python",
        "code": "   \n\t   ",
        "enable_ai": False
    })
    assert response.status_code == 422


def test_get_sample_snippets(client: TestClient):
    response = client.get("/api/v1/samples/")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 3
    assert any(s["id"] == "py-sqli-auth" for s in samples)


def test_health_and_readiness_probes(client: TestClient):
    res_health = client.get("/api/v1/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    res_ready = client.get("/api/v1/ready")
    assert res_ready.status_code == 200
    assert res_ready.json()["status"] == "ready"


def test_analyze_python_syntax_error_limitations(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Broken Python Syntax",
        "language": "python",
        "code": "def broken_func(\n    print('unclosed paren')",
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed_with_limitations"
    assert len(data["findings"]) >= 1
    syntax_finding = next(f for f in data["findings"] if f["rule_id"] == "SYN-PY-001")
    assert syntax_finding["line_start"] is not None
    assert syntax_finding["evidence"] is not None


def test_analyze_javascript_vulnerabilities(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "JS XSS and Equality",
        "language": "javascript",
        "code": "function render(input) {\n  element.innerHTML = input;\n  if (input == null) return false;\n}",
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed"
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "SEC-JS-001" in rule_ids
    assert "BUG-JS-001" in rule_ids


def test_analyze_java_vulnerabilities(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Java SQLi and Equals",
        "language": "java",
        "code": "public class UserService {\n  void find(Statement stmt, String id, String token) {\n    stmt.executeQuery(\"SELECT * FROM users WHERE id = '\" + id + \"'\");\n    if (token == \"SECRET\") {}\n  }\n}",
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed"
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "SEC-JV-001" in rule_ids
    assert "BUG-JV-001" in rule_ids


def test_auto_language_detection(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Auto Detect Python",
        "language": "auto",
        "code": "import os\ndef test():\n    return os.environ.get('SECRET')",
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["language"] == "python"


def test_unsupported_language_graceful_handling(client: TestClient):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Cobol Code",
        "language": "cobol",
        "code": "IDENTIFICATION DIVISION.\nPROGRAM-ID. HELLO-WORLD.\nPROCEDURE DIVISION.\nDISPLAY 'HELLO'.\nSTOP RUN.",
        "enable_ai": False
    })
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "unsupported_language"
    assert "cobol" in data["coverage_summary"].lower()


def test_language_capabilities_matrix_endpoint(client: TestClient):
    response = client.get("/api/v1/languages/")
    assert response.status_code == 200
    languages = response.json()
    assert len(languages) >= 4
    lang_ids = [l["id"] for l in languages]
    assert "python" in lang_ids
    assert "javascript" in lang_ids
    assert "typescript" in lang_ids
    assert "java" in lang_ids


def test_student_management_system_api_regression(client: TestClient, student_management_code: str):
    response = client.post("/api/v1/reviews/analyze", json={
        "title": "Student Management System Regression",
        "language": "python",
        "code": student_management_code,
        "enable_ai": True
    })
    assert response.status_code == 201
    data = response.json()

    assert data["status"] == "completed"
    assert data["language"] == "python"
    assert data["quality_score"] == 50
    assert data["security_score"] == 100
    assert len(data["findings"]) == 4

    rules = {f["rule_id"] for f in data["findings"]}
    assert "BUG-PY-006" in rules  # missing attendance key
    assert "BUG-PY-007" in rules  # unsafe empty marks list division
    assert "BUG-PY-008" in rules  # inconsistent case search
    assert "VAL-PY-001" in rules  # missing validation for negative age

    # Verify each finding has required fields
    for finding in data["findings"]:
        assert finding["line_start"] is not None
        assert finding["severity"] in ("critical", "high", "medium", "low", "info")
        assert finding["source"] in ("static", "ai")
        assert finding["evidence"] is not None
        assert finding["suggested_fix"] is not None
