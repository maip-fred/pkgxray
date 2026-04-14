"""Tests for ObfuscationAnalyzer."""

from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_exec_base64_combined():
    analyzer = ObfuscationAnalyzer()
    code = 'import base64\nexec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_base64_standalone_not_flagged():
    """base64.b64decode() aislado es legítimo (auth headers, imágenes, TLS); no debe flaggarse."""
    analyzer = ObfuscationAnalyzer()
    code = 'import base64\ndata = base64.b64decode("c29tZXRoaW5n")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) == 0


def test_detects_bytes_fromhex():
    analyzer = ObfuscationAnalyzer()
    code = 'payload = bytes.fromhex("deadbeef")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1


def test_safe_code_no_findings():
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze('x = "hello world"\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze('import base64\nexec(base64.b64decode("test"))', 'test.py')
    assert all(f.analyzer_name == "obfuscation" for f in findings)
