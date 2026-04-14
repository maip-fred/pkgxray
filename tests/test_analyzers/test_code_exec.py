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
