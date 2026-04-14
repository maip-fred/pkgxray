"""Tests for DynamicImportAnalyzer."""

from pkgxray.analyzers.dynamic_imports import DynamicImportAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_dunder_import():
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('__import__("os")', 'test.py')
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detects_importlib_import_module_static():
    analyzer = DynamicImportAnalyzer()
    findings = analyzer.analyze('import importlib\nimportlib.import_module("json")', 'test.py')
    assert len(findings) >= 1
    # Static string literal → MEDIUM
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_detects_importlib_import_module_dynamic():
    analyzer = DynamicImportAnalyzer()
    code = 'import importlib\nmod_name = "mod"\nimportlib.import_module("hidden_" + mod_name)'
    findings = analyzer.analyze(code, 'test.py')
    # Dynamic argument → HIGH
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


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
