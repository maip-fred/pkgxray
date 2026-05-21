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


def test_aliased_importlib_detected():
    """import importlib as il; il.import_module('os') must be detected."""
    analyzer = DynamicImportAnalyzer()
    code = "import importlib as il\nil.import_module('os')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased importlib.import_module must be detected"
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_aliased_importlib_in_function_detected():
    """import importlib as il inside function → MEDIUM for static arg."""
    analyzer = DynamicImportAnalyzer()
    code = "def loader():\n    import importlib as il\n    il.import_module('json')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_unrelated_alias_not_flagged():
    """import os as il; il.import_module('x') must NOT be flagged (os ≠ importlib)."""
    analyzer = DynamicImportAnalyzer()
    code = "import os as il\nil.import_module('x')\n"
    findings = analyzer.analyze(code, "test.py")
    assert findings == [], "os aliased as 'il' must not trigger importlib check"


# ── #11: importlib.util.spec_from_file_location ──────────────────────────────

def test_detects_spec_from_file_location():
    """importlib.util.spec_from_file_location() must be detected — loads arbitrary files."""
    analyzer = DynamicImportAnalyzer()
    code = (
        "import importlib\n"
        "def load_plugin(path):\n"
        "    spec = importlib.util.spec_from_file_location('mod', path)\n"
    )
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "importlib.util.spec_from_file_location must be detected"
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_spec_from_file_location_at_module_level_critical():
    """importlib.util.spec_from_file_location() at module level → CRITICAL."""
    analyzer = DynamicImportAnalyzer()
    code = (
        "import importlib\n"
        "spec = importlib.util.spec_from_file_location('evil', '/tmp/payload.py')\n"
    )
    findings = analyzer.analyze(code, "test.py")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_non_importlib_spec_from_file_location_not_flagged():
    """other.util.spec_from_file_location() must NOT be flagged (not importlib)."""
    analyzer = DynamicImportAnalyzer()
    code = "import mylib\nspec = mylib.util.spec_from_file_location('x', 'y')\n"
    findings = analyzer.analyze(code, "test.py")
    assert findings == []
