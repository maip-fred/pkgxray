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
    """os.remove() al nivel del módulo → CRITICAL (se ejecuta al importar)."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('import os\nos.remove("/data/file")', 'test.py')
    remove_findings = [f for f in findings if "remove" in f.description]
    assert len(remove_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in remove_findings)


def test_detects_os_remove_in_function():
    """os.remove() dentro de una función → HIGH (no escalado)."""
    analyzer = FilesystemAnalyzer()
    code = 'def cleanup():\n    os.remove("/data/file")'
    findings = analyzer.analyze(code, 'test.py')
    remove_findings = [f for f in findings if "remove" in f.description]
    assert len(remove_findings) >= 1
    assert any(f.severity == Severity.HIGH for f in remove_findings)


def test_detects_shutil_rmtree():
    """shutil.rmtree() al nivel del módulo → CRITICAL."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('import shutil\nshutil.rmtree("/data/dir")', 'test.py')
    rmtree_findings = [f for f in findings if "rmtree" in f.description]
    assert len(rmtree_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in rmtree_findings)


def test_detects_shutil_rmtree_in_function():
    """shutil.rmtree() dentro de una función → HIGH."""
    analyzer = FilesystemAnalyzer()
    code = 'def cleanup():\n    shutil.rmtree("/data/dir")'
    findings = analyzer.analyze(code, 'test.py')
    rmtree_findings = [f for f in findings if "rmtree" in f.description]
    assert len(rmtree_findings) >= 1
    assert any(f.severity == Severity.HIGH for f in rmtree_findings)


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


# ── P2-01: receptor filtering (list.remove falso positivo) ───────────────────

def test_list_remove_not_flagged():
    """my_list.remove(x) no debe generar findings — no es una op. de filesystem."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('items = [1,2,3]\nitems.remove(2)', 'test.py')
    remove_findings = [f for f in findings if "remove" in f.description]
    assert len(remove_findings) == 0


def test_set_remove_not_flagged():
    """my_set.remove(x) no debe generar findings."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('s = {1,2}\ns.remove(1)', 'test.py')
    remove_findings = [f for f in findings if "remove" in f.description]
    assert len(remove_findings) == 0


def test_path_unlink_flagged():
    """Path('f').unlink() debe generar findings — receptor es Path."""
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('from pathlib import Path\nPath("evil.sh").unlink()', 'test.py')
    unlink_findings = [f for f in findings if "unlink" in f.description]
    assert len(unlink_findings) >= 1


# ── P2-04: ClassDef no es barrera para is_module_level ───────────────────────

def test_class_body_treated_as_module_level():
    """shutil.rmtree() en cuerpo de clase → CRITICAL (corre al importar)."""
    analyzer = FilesystemAnalyzer()
    code = 'class Malicious:\n    shutil.rmtree("/root")'
    findings = analyzer.analyze(code, 'test.py')
    rmtree_findings = [f for f in findings if "rmtree" in f.description]
    assert len(rmtree_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in rmtree_findings)


# ── P2-06: rutas sensibles expandidas ────────────────────────────────────────

def test_detects_kube_config():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "~/.kube/config"', 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_npmrc():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "~/.npmrc"', 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detects_pypirc():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "~/.pypirc"', 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detects_bash_profile():
    analyzer = FilesystemAnalyzer()
    findings = analyzer.analyze('path = "~/.bash_profile"', 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)
