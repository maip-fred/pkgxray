"""Tests for DynamicImportAnalyzer."""

from pkgxray.analyzers.dynamic_imports import DynamicImportAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_dunder_import():
    """__import__("os") al nivel del módulo → CRITICAL (escalado por module-level)."""
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('__import__("os")', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_dunder_import_static_in_function():
    """__import__("json") dentro de función → MEDIUM (arg estático, no escalado)."""
    analyzer = DynamicImportAnalyzer()
    code = 'def foo():\n    __import__("json")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_dunder_import_dynamic_in_function():
    """__import__(var) dentro de función → HIGH (arg dinámico)."""
    analyzer = DynamicImportAnalyzer()
    code = 'def foo():\n    __import__(user_input)'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detects_importlib_import_module_static():
    """importlib.import_module("json") al nivel del módulo → CRITICAL."""
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('import importlib\nimportlib.import_module("json")', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_importlib_static_in_function():
    """importlib.import_module("json") dentro de función → MEDIUM (arg estático)."""
    analyzer = DynamicImportAnalyzer()
    code = 'def load(name):\n    import importlib\n    return importlib.import_module("json")'
    findings = analyzer.analyze(code, 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_detects_importlib_import_module_dynamic():
    """importlib.import_module() con arg dinámico al nivel del módulo → CRITICAL."""
    analyzer = DynamicImportAnalyzer()
    code = 'import importlib\nmod_name = "mod"\nimportlib.import_module("hidden_" + mod_name)'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_importlib_dynamic_in_function():
    """importlib.import_module() con arg dinámico dentro de función → HIGH."""
    analyzer = DynamicImportAnalyzer()
    code = 'def loader(name):\n    import importlib\n    importlib.import_module("hidden_" + name)'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


def test_some_obj_import_module_not_flagged():
    """some_obj.import_module("x") no debe generar findings — receptor no es importlib."""
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('some_obj.import_module("x")', 'test.py')
    assert len(findings) == 0


def test_safe_code_no_findings():
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('import os\nimport json', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('__import__("os")', 'test.py')
    assert all(f.analyzer_name == "dynamic_imports" for f in findings)
