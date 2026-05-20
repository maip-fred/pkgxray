"""Tests for Fix 2 (TOMLLIB_AVAILABLE) and Fix 3 (pre-computed tree/parent_map)."""

import ast
import unittest.mock as mock

import pytest

from pkgxray.analyzers.base import build_parent_map
from pkgxray.analyzers.config_files import TOMLLIB_AVAILABLE
from pkgxray.analyzers.code_exec import CodeExecAnalyzer
from pkgxray.analyzers.network import NetworkAnalyzer
from pkgxray.analyzers.filesystem import FilesystemAnalyzer
from pkgxray.analyzers.env_access import EnvAccessAnalyzer
from pkgxray.analyzers.subprocess_calls import SubprocessAnalyzer
from pkgxray.analyzers.dynamic_imports import DynamicImportAnalyzer
from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer


# ---------------------------------------------------------------------------
# TOMLLIB_AVAILABLE is a bool exported from config_files
# ---------------------------------------------------------------------------

def test_tomllib_available_is_bool():
    assert isinstance(TOMLLIB_AVAILABLE, bool)


def test_tomllib_available_true_on_py311_plus():
    """On Python 3.11+ tomllib is in stdlib — TOMLLIB_AVAILABLE must be True."""
    import sys
    if sys.version_info >= (3, 11):
        assert TOMLLIB_AVAILABLE is True


# ---------------------------------------------------------------------------
# Analyzers accept pre-computed tree / parent_map (Fix 3)
# ---------------------------------------------------------------------------

_SAFE_CODE = "x = 1 + 2\n"

_ANALYZERS_WITH_PARENT_MAP = [
    CodeExecAnalyzer(),
    NetworkAnalyzer(),
    FilesystemAnalyzer(),
    EnvAccessAnalyzer(),
    SubprocessAnalyzer(),
    DynamicImportAnalyzer(),
]

_ALL_AST_ANALYZERS = _ANALYZERS_WITH_PARENT_MAP + [
    ObfuscationAnalyzer(),
    SetupScriptAnalyzer(),
]


@pytest.mark.parametrize("analyzer", _ALL_AST_ANALYZERS, ids=lambda a: a.name)
def test_analyzer_accepts_precomputed_tree(analyzer):
    """All AST analyzers must accept a pre-computed tree without error."""
    tree = ast.parse(_SAFE_CODE)
    parent_map = build_parent_map(tree)
    findings = analyzer.analyze(_SAFE_CODE, "test.py", tree=tree, parent_map=parent_map)
    assert isinstance(findings, list)


@pytest.mark.parametrize("analyzer", _ANALYZERS_WITH_PARENT_MAP, ids=lambda a: a.name)
def test_build_parent_map_not_called_when_provided(analyzer):
    """When parent_map is provided, the analyzer must NOT rebuild it."""
    tree = ast.parse(_SAFE_CODE)
    parent_map = build_parent_map(tree)

    with mock.patch(
        "pkgxray.analyzers.base.build_parent_map", wraps=build_parent_map
    ) as mock_bpm:
        analyzer.analyze(_SAFE_CODE, "test.py", tree=tree, parent_map=parent_map)
        mock_bpm.assert_not_called()


@pytest.mark.parametrize("analyzer", _ANALYZERS_WITH_PARENT_MAP, ids=lambda a: a.name)
def test_build_parent_map_called_when_not_provided(analyzer):
    """When parent_map is NOT provided, the analyzer must build it itself."""
    import sys
    # Each analyzer has its own local reference to build_parent_map obtained via
    # `from pkgxray.analyzers.base import build_parent_map`.  Patching the base
    # module would not affect that reference; we must patch the analyzer's own module.
    analyzer_module = sys.modules[type(analyzer).__module__]
    with mock.patch.object(analyzer_module, "build_parent_map", wraps=build_parent_map) as mock_bpm:
        analyzer.analyze(_SAFE_CODE, "test.py")
        mock_bpm.assert_called_once()


# ---------------------------------------------------------------------------
# Scanner integration: tree built once, not N times per file
# ---------------------------------------------------------------------------

def test_scanner_builds_tree_once_per_file(monkeypatch):
    """The scanner must call ast.parse() once per .py file, not once per analyzer."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.downloader as dl_mod
    import pkgxray.extractor as ext_mod
    from pkgxray.analyzers.base import ExtractedFile

    monkeypatch.setattr(dl_mod, "download_package", lambda *a, **kw: ("/fake/path", "1.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: (
        [ExtractedFile(filename="module.py", content="x = 1\n")], 0,
    ))

    parse_call_count = 0
    real_parse = ast.parse

    def counting_parse(source, *args, **kwargs):
        nonlocal parse_call_count
        parse_call_count += 1
        return real_parse(source, *args, **kwargs)

    monkeypatch.setattr(scanner_mod.ast, "parse", counting_parse)

    scanner_mod.scan("fake-pkg")

    assert parse_call_count == 1, (
        f"Expected ast.parse to be called once per file, but it was called {parse_call_count} times"
    )


# ---------------------------------------------------------------------------
# Scanner: tomllib_unavailable is recorded in skipped_files
# ---------------------------------------------------------------------------

def test_scanner_records_skipped_pyproject_when_tomllib_unavailable(monkeypatch):
    """When TOMLLIB_AVAILABLE is False, pyproject.toml must appear in skipped_files."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.downloader as dl_mod
    import pkgxray.extractor as ext_mod
    from pkgxray.analyzers.base import ExtractedFile

    monkeypatch.setattr(dl_mod, "download_package", lambda *a, **kw: ("/fake/path", "1.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: (
        [ExtractedFile(
            filename="pyproject.toml",
            content='[build-system]\nrequires = ["setuptools"]\n',
            is_config=True,
        )], 0,
    ))
    monkeypatch.setattr(scanner_mod, "TOMLLIB_AVAILABLE", False)

    result = scanner_mod.scan("fake-pkg")

    reasons = [s["reason"] for s in result.skipped_files]
    assert "tomllib_unavailable" in reasons


def test_scanner_does_not_skip_setup_cfg_when_tomllib_unavailable(monkeypatch):
    """setup.cfg uses configparser (always available) — must NOT be skipped."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.downloader as dl_mod
    import pkgxray.extractor as ext_mod
    from pkgxray.analyzers.base import ExtractedFile

    monkeypatch.setattr(dl_mod, "download_package", lambda *a, **kw: ("/fake/path", "1.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: (
        [ExtractedFile(
            filename="setup.cfg",
            content="[metadata]\nname = mypkg\n",
            is_config=True,
        )], 0,
    ))
    monkeypatch.setattr(scanner_mod, "TOMLLIB_AVAILABLE", False)

    result = scanner_mod.scan("fake-pkg")

    assert result.skipped_files == []
