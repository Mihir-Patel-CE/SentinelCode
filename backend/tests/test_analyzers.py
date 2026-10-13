from app.services.analyzers.python_ast import PythonAnalyzer
from app.services.analyzers.javascript import JavaScriptAnalyzer
from app.services.analyzers.java import JavaAnalyzer
from app.services.analyzers.registry import registry
from app.services.scoring import ScoringEngine


def test_python_analyzer_sql_injection_and_evidence():
    analyzer = PythonAnalyzer()
    code = 'def get_user(db, uid):\n    db.execute(f"SELECT * FROM users WHERE id = {uid}")'
    res = analyzer.analyze(code)
    assert res.status == "completed"
    findings = res.findings
    sqli = next((f for f in findings if f.rule_id == "SEC-PY-001"), None)
    assert sqli is not None
    assert sqli.severity == "critical"
    assert sqli.line_start == 2
    assert "SELECT * FROM users" in (sqli.evidence or "")


def test_python_analyzer_syntax_error():
    analyzer = PythonAnalyzer()
    code = 'def broken_function(\n    return "missing closing paren"'
    res = analyzer.analyze(code)
    assert res.status == "completed_with_limitations"
    assert any(f.rule_id == "SYN-PY-001" and f.category == "syntax" for f in res.findings)


def test_python_analyzer_undefined_variable():
    analyzer = PythonAnalyzer()
    code = 'def compute_total():\n    return subtotal + tax'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-PY-004" and "subtotal" in f.title for f in res.findings)


def test_python_analyzer_dead_code():
    analyzer = PythonAnalyzer()
    code = 'def process():\n    return 42\n    print("unreachable")'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-PY-003" for f in res.findings)


def test_python_analyzer_zero_division():
    analyzer = PythonAnalyzer()
    code = 'def calc():\n    return 100 / 0'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-PY-005" for f in res.findings)


def test_python_analyzer_insecure_deserialization():
    analyzer = PythonAnalyzer()
    code = 'import pickle\ndef load(data):\n    return pickle.loads(data)'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "SEC-PY-003" and "pickle" in f.title.lower() for f in res.findings)


def test_python_analyzer_mutable_default():
    analyzer = PythonAnalyzer()
    code = 'def append_item(val, items=[]):\n    items.append(val)\n    return items'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-PY-001" for f in res.findings)


def test_python_analyzer_bare_except():
    analyzer = PythonAnalyzer()
    code = 'try:\n    risky_call()\nexcept:\n    pass'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-PY-002" for f in res.findings)


def test_javascript_analyzer_xss_and_evidence():
    analyzer = JavaScriptAnalyzer(is_typescript=False)
    code = 'function render(val) { element.innerHTML = val; }'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "SEC-JS-001" and f.category == "security" for f in res.findings)


def test_javascript_analyzer_syntax_unclosed_bracket():
    analyzer = JavaScriptAnalyzer(is_typescript=False)
    code = 'function test() { if (true) { console.log("oops"); }'
    res = analyzer.analyze(code)
    assert res.status == "completed_with_limitations"
    assert any(f.rule_id == "SYN-JS-002" for f in res.findings)


def test_javascript_analyzer_loose_equality():
    analyzer = JavaScriptAnalyzer(is_typescript=False)
    code = 'if (user.role == "admin") { grantAccess(); }'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "BUG-JS-001" for f in res.findings)


def test_typescript_analyzer_any_abuse():
    analyzer = JavaScriptAnalyzer(is_typescript=True)
    code = 'function handle(data: any): any { return data; }'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "TS-QUAL-001" for f in res.findings)


def test_java_analyzer_sql_injection():
    analyzer = JavaAnalyzer()
    code = 'Statement stmt = conn.createStatement(); stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "SEC-JV-001" for f in res.findings)


def test_java_analyzer_path_traversal():
    analyzer = JavaAnalyzer()
    code = 'File file = new File(baseDir + userInput);'
    res = analyzer.analyze(code)
    assert any(f.rule_id == "SEC-JV-002" for f in res.findings)


def test_registry_language_detection():
    py_code = "def calculate_sum(a, b):\n    return a + b"
    assert registry.detect_language(py_code) == "python"

    ts_code = "interface UserProfile {\n    name: string;\n    age: number;\n}"
    assert registry.detect_language(ts_code) == "typescript"

    java_code = "public class Application {\n    public static void main(String[] args) {}\n}"
    assert registry.detect_language(java_code) == "java"


def test_scoring_engine_proportional_penalties():
    clean_code = "def add(a, b):\n    return a + b"
    q_clean, s_clean, m_clean = ScoringEngine.calculate([], clean_code, "completed")
    assert q_clean == 100
    assert s_clean == 100
    assert m_clean >= 80

    # Failed analysis should return None scores
    q_fail, s_fail, m_fail = ScoringEngine.calculate([], clean_code, "failed")
    assert q_fail is None
    assert s_fail is None


def test_student_management_system_regression(student_management_code: str):
    analyzer = PythonAnalyzer()
    res = analyzer.analyze(student_management_code)

    assert res.status == "completed"
    assert len(res.findings) == 4

    findings_by_rule = {f.rule_id: f for f in res.findings}

    # 1. Missing dictionary key 'attendance'
    assert "BUG-PY-006" in findings_by_rule
    f_att = findings_by_rule["BUG-PY-006"]
    assert f_att.severity == "high"
    assert "attendance" in f_att.title
    assert f_att.line_start is not None
    assert "attendance" in (f_att.evidence or "").lower()

    # 2. Unsafe division by collection length (ZeroDivisionError)
    assert "BUG-PY-007" in findings_by_rule
    f_div = findings_by_rule["BUG-PY-007"]
    assert f_div.severity == "high"
    assert "marks" in f_div.title
    assert f_div.line_start is not None
    assert "len(marks)" in (f_div.evidence or "")

    # 3. Inconsistent case normalization
    assert "BUG-PY-008" in findings_by_rule
    f_case = findings_by_rule["BUG-PY-008"]
    assert f_case.severity == "medium"
    assert f_case.line_start is not None
    assert "keyword.lower()" in (f_case.evidence or "")

    # 4. Missing input validation for negative age
    assert "VAL-PY-001" in findings_by_rule
    f_val = findings_by_rule["VAL-PY-001"]
    assert f_val.severity == "low"
    assert f_val.category == "quality"
    assert "age" in f_val.title
    assert f_val.line_start is not None

    # Calculate scores from real findings
    q, s, m = ScoringEngine.calculate(res.findings, student_management_code, res.status)
    assert q == 50
    assert s == 100
    assert m is not None


def test_scoped_undefined_name_detection():
    analyzer = PythonAnalyzer()
    code_with_undefined = "def compute():\n    a = 1\n    return a + missing_var"
    res = analyzer.analyze(code_with_undefined)
    assert any(f.rule_id == "BUG-PY-004" and "missing_var" in f.title for f in res.findings)

    # Valid forward reference within a module should NOT be marked as undefined
    code_forward_ref = "def caller():\n    return target_fn()\ndef target_fn():\n    return 42"
    res_clean = analyzer.analyze(code_forward_ref)
    assert not any(f.rule_id == "BUG-PY-004" for f in res_clean.findings)
