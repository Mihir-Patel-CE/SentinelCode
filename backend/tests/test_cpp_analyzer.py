import pytest
from app.services.analyzers.cpp_analyzer import CppAnalyzer
from app.services.scoring import ScoringEngine


def test_valid_cpp_program_clean():
    """Valid, modern C++ program with RAII compiles cleanly without defect findings."""
    analyzer = CppAnalyzer()
    code = """#include <iostream>
#include <string>
#include <vector>
#include <memory>

class SafeWidget {
public:
    SafeWidget(std::string name) : name_(std::move(name)) {}
    const std::string& getName() const { return name_; }
private:
    std::string name_;
};

int main() {
    auto widget = std::make_unique<SafeWidget>("Sentinel");
    std::vector<int> items = {1, 2, 3};
    std::cout << widget->getName() << " size: " << items.size() << std::endl;
    return 0;
}
"""
    res = analyzer.analyze(code)
    assert res.status == "completed"
    bugs_or_sec = [f for f in res.findings if f.category in ("syntax", "security", "bug")]
    assert len(bugs_or_sec) == 0

    quality, security, maintainability = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is not None and quality >= 90
    assert security == 100


def test_cpp_syntax_error_not_critical_security():
    """C++ syntax errors are categorized as syntax, never labeled as critical security."""
    analyzer = CppAnalyzer()
    code = """#include <iostream>
int main() {
    std::cout << "Missing semicolon"
    return 0;
}
"""
    res = analyzer.analyze(code)
    assert res.status == "completed_with_limitations"
    syntax_findings = [f for f in res.findings if f.category == "syntax"]
    assert len(syntax_findings) > 0
    for sf in syntax_findings:
        assert sf.category == "syntax"
        assert sf.severity != "critical"

    quality, _, _ = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is not None and quality < 90


def test_cpp_out_of_bounds_detection():
    """Array out-of-bounds access is flagged as bug."""
    analyzer = CppAnalyzer()
    code = """void test() {
    int buffer[4];
    buffer[9] = 100;
}
"""
    res = analyzer.analyze(code)
    oob = next((f for f in res.findings if "OOB" in (f.rule_id or "") or "bounds" in (f.rule_id or "").lower() or "bounds" in f.title.lower()), None)
    assert oob is not None
    assert oob.category == "bug"
    assert oob.severity == "high"


def test_cpp_unmanaged_new_memory_leak():
    """Unmanaged raw new without delete is detected as a potential leak (CWE-401)."""
    analyzer = CppAnalyzer()
    code = """void leaky_func() {
    int *data = new int(42);
    // no delete
}
"""
    res = analyzer.analyze(code)
    leak = next((f for f in res.findings if "MEM" in (f.rule_id or "") or "leak" in f.title.lower()), None)
    assert leak is not None
    assert leak.category == "bug"


def test_cpp_new_array_delete_scalar_mismatch():
    """Array new[] paired with scalar delete is detected (CWE-762)."""
    analyzer = CppAnalyzer()
    code = """void mismatch_cleanup() {
    char *buf = new char[128];
    delete buf;
}
"""
    res = analyzer.analyze(code)
    mismatch = next((f for f in res.findings if f.rule_id == "BUG-CPP-002" or "mismatch" in f.title.lower()), None)
    assert mismatch is not None
    assert mismatch.category == "bug"
    assert mismatch.severity == "high"


def test_cpp_dangling_local_reference_return():
    """Returning a reference to a local stack variable is detected (CWE-562)."""
    analyzer = CppAnalyzer()
    code = """#include <string>
const std::string& getLocalString() {
    std::string str = "dangling";
    return str;
}
"""
    res = analyzer.analyze(code)
    dangling = next((f for f in res.findings if f.rule_id == "BUG-CPP-003" or "dangling" in f.title.lower()), None)
    assert dangling is not None
    assert dangling.category == "bug"
    assert dangling.severity in ("critical", "high")


def test_cpp_polymorphic_missing_virtual_destructor():
    """Polymorphic class missing virtual destructor is flagged (CWE-1079)."""
    analyzer = CppAnalyzer()
    code = """class BaseInterface {
public:
    virtual void execute() = 0;
    ~BaseInterface() {}
};
"""
    res = analyzer.analyze(code)
    vdestruct = next((f for f in res.findings if f.rule_id == "BUG-CPP-004" or "destructor" in f.title.lower()), None)
    assert vdestruct is not None
    assert vdestruct.category == "bug"


def test_cpp_exception_caught_by_value():
    """Catching exception by value is detected as object slicing quality issue."""
    analyzer = CppAnalyzer()
    code = """#include <stdexcept>
void run() {
    try {
        throw std::runtime_error("failed");
    } catch (std::runtime_error err) {
        // caught by value
    }
}
"""
    res = analyzer.analyze(code)
    slicing = next((f for f in res.findings if f.rule_id == "BUG-CPP-005" or "slicing" in f.title.lower() or "value" in f.title.lower()), None)
    assert slicing is not None
    assert slicing.category == "quality"


def test_cpp_mutex_lock_without_raii_guard():
    """Direct mutex .lock() without RAII wrapper is flagged (CWE-833)."""
    analyzer = CppAnalyzer()
    code = """#include <mutex>
std::mutex mtx;
void critical_work() {
    mtx.lock();
    mtx.unlock();
}
"""
    res = analyzer.analyze(code)
    mutex_finding = next((f for f in res.findings if f.rule_id == "BUG-CPP-006" or "mutex" in f.title.lower()), None)
    assert mutex_finding is not None
    assert mutex_finding.category == "bug"


def test_cpp_use_after_free_detection():
    """Accessing memory after calling delete is detected as Use-After-Free (CWE-416)."""
    analyzer = CppAnalyzer()
    code = """void test_uaf() {
    int *p = new int(10);
    delete p;
    *p = 20;
}
"""
    res = analyzer.analyze(code)
    uaf = next((f for f in res.findings if "UAF" in (f.rule_id or "") or "after-free" in (f.rule_id or "").lower() or "after it is freed" in f.description.lower() or "use-after-free" in f.title.lower()), None)
    assert uaf is not None
    assert uaf.category == "security"
    assert uaf.severity == "critical"


def test_cpp_compiler_unavailable_reports_configuration_error():
    """If C++ compiler is unavailable, reports clear configuration error and status='failed'."""
    analyzer = CppAnalyzer(compiler_cmd="nonexistent-clangpp-compiler-xyz")
    code = "int main() { return 0; }"
    res = analyzer.analyze(code)
    assert res.status == "failed"
    assert res.error_message is not None
    assert "Analyzer unavailable" in res.error_message or "not available" in res.error_message
    assert len(res.findings) == 0

    quality, security, maintainability = ScoringEngine.calculate(
        findings=res.findings,
        code=code,
        status=res.status
    )
    assert quality is None
    assert security is None
    assert maintainability is None
