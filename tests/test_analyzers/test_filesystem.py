"""Tests for FilesystemAnalyzer."""

from pkgxray.analyzers.filesystem import FilesystemAnalyzer
from pkgxray.analyzers.base import Severity


def test_open_write_not_flagged():
    """open() en modo escritura es demasiado común; no debe generar findings por sí solo."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('open("/tmp/data.txt", "w")', 'test.py')
    write_findings = [f for f in findings if "escritura" in f.description or "write" in f.description.lower()]
    assert len(write_findings) == 0


def test_open_write_sensitive_path_flagged():
    """open() sobre una ruta sensible sí debe flaggearse por la ruta."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('open("/etc/passwd", "w")', 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_os_remove():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('import os\nos.remove("/tmp/file")', 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH and "remove" in f.description]
    assert len(high) >= 1


def test_detects_shutil_rmtree():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('import shutil\nshutil.rmtree("/tmp/dir")', 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_detects_sensitive_path_passwd():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "/etc/passwd"', 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_detects_sensitive_path_ssh():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('key = open("~/.ssh/id_rsa").read()', 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_safe_code_no_findings():
    analyzer = FilesystemAnalyzer()
    # open in read mode should not trigger
    findings = analyzer.analyze('with open("config.json", "r") as f:\n    data = f.read()', 'test.py')
    write_findings = [f for f in findings if "write" in f.description.lower() or "write mode" in f.description.lower()]
    assert len(write_findings) == 0


def test_syntax_error_no_crash():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "/etc/passwd"', 'test.py')
    assert all(f.analyzer_name == "filesystem" for f in findings)
