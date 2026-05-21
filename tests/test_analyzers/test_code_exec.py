"""Tests for CodeExecAnalyzer."""

from pkgxray.analyzers.code_exec import CodeExecAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_eval():
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('result = eval(user_input)', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_detects_exec():
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('exec(some_code)', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_compile_at_module_level():
    """compile() al nivel del módulo → CRITICAL (se ejecuta al importar)."""
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('code = compile(source, "file.py", "exec")', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_compile_in_function():
    """compile() dentro de una función → HIGH."""
    analyzer = CodeExecAnalyzer()
    code = 'def build():\n    code = compile(source, "file.py", "exec")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)


def test_safe_code_no_findings():
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = CodeExecAnalyzer()
    findings = analyzer.analyze('eval("x")', 'test.py')
    assert findings[0].analyzer_name == "code_exec"


def test_finding_has_line_number():
    analyzer = CodeExecAnalyzer()
    code = 'x = 1\nexec("bad code")\n'
    findings = analyzer.analyze(code, 'test.py')
    assert findings[0].line_number == 2


def test_class_body_treated_as_module_level():
    """exec() en cuerpo de clase → CRITICAL (el cuerpo de clase corre al importar)."""
    analyzer = CodeExecAnalyzer()
    code = 'class Malicious:\n    exec("payload")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


# ── #4: ctypes detection ─────────────────────────────────────────────────────

def test_detects_ctypes_cdll():
    """ctypes.CDLL('evil.so') must be detected as CRITICAL."""
    analyzer = CodeExecAnalyzer()
    code = 'import ctypes\ndef load():\n    ctypes.CDLL("/tmp/evil.so")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("ctypes" in f.description for f in findings)


def test_detects_ctypes_cdll_loadlibrary():
    """ctypes.cdll.LoadLibrary('evil.so') must be detected as CRITICAL."""
    analyzer = CodeExecAnalyzer()
    code = 'import ctypes\ndef load():\n    ctypes.cdll.LoadLibrary("/tmp/evil.so")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_ctypes_aliased():
    """import ctypes as ct; ct.CDLL('lib.so') must be detected."""
    analyzer = CodeExecAnalyzer()
    code = 'import ctypes as ct\ndef load():\n    ct.CDLL("evil.so")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1


def test_ctypes_at_module_level_critical():
    """ctypes.CDLL() at module level → CRITICAL (runs on import)."""
    analyzer = CodeExecAnalyzer()
    code = 'import ctypes\nctypes.CDLL("/tmp/backdoor.so")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


# ── #5: variable-assignment aliasing ─────────────────────────────────────────

def test_detects_variable_alias_exec():
    """e = exec; e('payload') must be detected."""
    analyzer = CodeExecAnalyzer()
    code = 'e = exec\ne("import os; os.system(\'id\')")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1, "Variable alias of exec must be detected"


def test_detects_variable_alias_eval():
    """run = eval; run(code) must be detected."""
    analyzer = CodeExecAnalyzer()
    code = 'def run_code():\n    run = eval\n    run(user_input)'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1, "Variable alias of eval must be detected"
