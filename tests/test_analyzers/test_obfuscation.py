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


# ── #22: previously uncovered branches ───────────────────────────────────────

def test_detects_codecs_decode_rot13():
    """codecs.decode() con rot13 → MEDIUM (técnica de ofuscación)."""
    analyzer = ObfuscationAnalyzer()
    code = 'import codecs\nresult = codecs.decode(b"vzcbeg bf", "rot13")'
    findings = analyzer.analyze(code, 'test.py')
    medium = [f for f in findings if f.severity == Severity.MEDIUM and "rot" in f.description]
    assert len(medium) >= 1


def test_hex_escape_string_detected():
    """String con ≥10 escapes hexadecimales → HIGH (posible payload ofuscado)."""
    analyzer = ObfuscationAnalyzer()
    # 110 × \x41 → decoded value = 110 chars (> 100 threshold), 110 consecutive \xNN in source
    hex_seq = "\\x41" * 110
    code = f'data = "{hex_seq}"'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


# ── #9: split base64 + exec across two statements ────────────────────────────

def test_detects_split_base64_exec():
    """payload = b64decode(...); exec(payload) must be detected as CRITICAL."""
    analyzer = ObfuscationAnalyzer()
    code = (
        'import base64\n'
        'payload = base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk=")\n'
        'exec(payload)\n'
    )
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_split_b64decode_standalone_not_flagged():
    """payload = b64decode(...) alone (no exec) must NOT be flagged."""
    analyzer = ObfuscationAnalyzer()
    code = 'import base64\npayload = base64.b64decode("c29tZXRoaW5n")\nprint(payload)\n'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) == 0


# ── #10: exec(compile(b64decode(...))) ────────────────────────────────────────

def test_detects_exec_compile_b64decode():
    """exec(compile(base64.b64decode(...), ...)) must be detected as CRITICAL."""
    analyzer = ObfuscationAnalyzer()
    code = (
        'import base64\n'
        'exec(compile(base64.b64decode("aW1wb3J0IG9z"), "<string>", "exec"))\n'
    )
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


# ── Phase 8 A5 tests ─────────────────────────────────────────────────────────

def test_exec_compile_b64decode_detected():
    """exec(compile(base64.b64decode(...), ...)) must be detected as CRITICAL."""
    from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
    from pkgxray.analyzers.base import Severity
    code = (
        "import base64\n"
        "exec(compile(base64.b64decode('aW1wb3J0IG9z'), '<string>', 'exec'))\n"
    )
    findings = ObfuscationAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_codecs_rot13_detected():
    """codecs.decode(data, 'rot13') must be detected as MEDIUM (currently uncovered)."""
    from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
    from pkgxray.analyzers.base import Severity
    code = "import codecs\nresult = codecs.decode('uryyb jbeyq', 'rot13')\n"
    findings = ObfuscationAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_bytes_fromhex_detected():
    """bytes.fromhex() must be detected as MEDIUM (currently uncovered)."""
    from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
    from pkgxray.analyzers.base import Severity
    code = "payload = bytes.fromhex('48656c6c6f20576f726c64')\n"
    findings = ObfuscationAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in findings)
