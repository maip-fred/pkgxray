"""Tests for EnvAccessAnalyzer."""

from pkgxray.analyzers.env_access import EnvAccessAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_os_environ_subscript():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.environ["HOME"]', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_detects_os_getenv():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("PATH")', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_detects_os_environ_get():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.environ.get("DEBUG", "false")', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_sensitive_variable_upgrades_severity():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("AWS_SECRET_KEY")', 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_sensitive_token_upgrades_severity():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nkey = os.environ["API_TOKEN"]', 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_safe_code_no_findings():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("X")', 'test.py')
    assert all(f.analyzer_name == "env_access" for f in findings)
