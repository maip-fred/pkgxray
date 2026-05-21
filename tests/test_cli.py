"""Tests for the CLI — --fail-above y --verbose flags."""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pkgxray.analyzers.base import ScanResult
from pkgxray.cli import main
from pkgxray.downloader import PackageNotFoundError, DownloadError


def _make_result(score: int, level: str = "LOW") -> ScanResult:
    """Crea un ScanResult sintético con el score indicado."""
    return ScanResult(
        package_name="test-pkg",
        version="1.0.0",
        scan_date="2025-01-01T00:00:00+00:00",
        findings=[],
        risk_score=score,
        risk_level=level,
        files_analyzed=3,
        summary={"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        skipped_files=[],
    )


# ── P4-01: --fail-above ───────────────────────────────────────────────────────

class TestFailAbove:
    def test_exits_1_when_score_exceeds_threshold(self):
        """Score 75 >= 50 → exit code 1."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(75, "CRITICAL")):
            result = runner.invoke(main, ["scan", "test-pkg", "--fail-above", "50"])
        assert result.exit_code == 1

    def test_exits_1_when_score_equals_threshold(self):
        """Score 50 >= 50 → exit code 1 (límite inclusivo)."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(50, "MODERATE")):
            result = runner.invoke(main, ["scan", "test-pkg", "--fail-above", "50"])
        assert result.exit_code == 1

    def test_exits_0_when_score_below_threshold(self):
        """Score 20 < 50 → exit code 0."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(20, "LOW")):
            result = runner.invoke(main, ["scan", "test-pkg", "--fail-above", "50"])
        assert result.exit_code == 0

    def test_no_flag_exits_0_regardless_of_score(self):
        """Sin --fail-above siempre sale 0, aunque el score sea CRITICAL."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(99, "CRITICAL")):
            result = runner.invoke(main, ["scan", "test-pkg"])
        assert result.exit_code == 0

    def test_output_mentions_score_and_threshold_on_failure(self):
        """El mensaje de error debe mencionar el score y el umbral."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(80, "CRITICAL")):
            result = runner.invoke(main, ["scan", "test-pkg", "--fail-above", "70"])
        assert "80" in result.output
        assert "70" in result.output

    def test_package_not_found_still_exits_1(self):
        """PackageNotFoundError → exit code 1 (comportamiento original intacto)."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", side_effect=PackageNotFoundError("test-pkg")):
            result = runner.invoke(main, ["scan", "test-pkg", "--fail-above", "50"])
        assert result.exit_code == 1

    def test_download_error_still_exits_1(self):
        """DownloadError → exit code 1 (comportamiento original intacto)."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", side_effect=DownloadError("timeout")):
            result = runner.invoke(main, ["scan", "test-pkg"])
        assert result.exit_code == 1


# ── P4-04: --verbose / logging ────────────────────────────────────────────────

class TestVerboseFlag:
    def test_verbose_flag_accepted(self):
        """--verbose no debe causar error de parseo de argumentos."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(10, "LOW")):
            result = runner.invoke(main, ["scan", "test-pkg", "--verbose"])
        assert result.exit_code == 0

    def test_without_verbose_no_debug_logs(self, caplog):
        """Sin --verbose no se emiten logs DEBUG del scanner."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(10, "LOW")):
            with caplog.at_level(logging.DEBUG, logger="pkgxray.scanner"):
                runner.invoke(main, ["scan", "test-pkg"])
        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(debug_records) == 0


# ── P4-04: logging en scanner ─────────────────────────────────────────────────

class TestScannerLogging:
    def _make_broken_analyzer(self):
        """Crea un analizador que siempre lanza RuntimeError."""
        from pkgxray.analyzers.base import BaseAnalyzer

        class BrokenAnalyzer(BaseAnalyzer):
            name = "broken_test"

            def analyze(self, source_code, filename):
                raise RuntimeError("fallo simulado")

        return BrokenAnalyzer()

    def _make_extracted_file(self):
        from pkgxray.analyzers.base import ExtractedFile
        return ExtractedFile(filename="test_module.py", content="x = 1", is_setup=False)

    def test_analyzer_failure_emits_warning(self, caplog, tmp_path):
        """Cuando un analizador falla, debe emitirse un WARNING con el nombre del analizador."""
        archive = tmp_path / "pkg-1.0.tar.gz"
        archive.write_bytes(b"")

        broken = self._make_broken_analyzer()
        extracted = self._make_extracted_file()

        _fake_info = {
            "info": {"version": "1.0"},
            "urls": [{"url": "http://x/pkg-1.0.tar.gz", "filename": "pkg-1.0.tar.gz",
                      "packagetype": "sdist", "digests": {}}],
        }
        with patch("pkgxray.scanner.downloader.get_package_info", return_value=_fake_info):
            with patch("pkgxray.scanner.downloader.download_file", return_value=archive):
                with patch("pkgxray.scanner.extractor.extract_python_files", return_value=([extracted], 0)):
                    with patch("pkgxray.scanner.get_all_analyzers", return_value=[broken]):
                        with caplog.at_level(logging.WARNING, logger="pkgxray.scanner"):
                            from pkgxray.scanner import scan
                            scan("test-pkg")

        warning_texts = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("broken_test" in msg for msg in warning_texts), (
            f"Expected warning mentioning 'broken_test', got: {warning_texts}"
        )

    def test_scan_continues_after_analyzer_failure(self, tmp_path):
        """El scan debe completarse aunque un analizador falle (fail-open)."""
        archive = tmp_path / "pkg-1.0.tar.gz"
        archive.write_bytes(b"")

        broken = self._make_broken_analyzer()
        extracted = self._make_extracted_file()

        _fake_info = {
            "info": {"version": "1.0"},
            "urls": [{"url": "http://x/pkg-1.0.tar.gz", "filename": "pkg-1.0.tar.gz",
                      "packagetype": "sdist", "digests": {}}],
        }
        with patch("pkgxray.scanner.downloader.get_package_info", return_value=_fake_info):
            with patch("pkgxray.scanner.downloader.download_file", return_value=archive):
                with patch("pkgxray.scanner.extractor.extract_python_files", return_value=([extracted], 0)):
                    with patch("pkgxray.scanner.get_all_analyzers", return_value=[broken]):
                        from pkgxray.scanner import scan
                        result = scan("test-pkg")

        assert result.risk_score == 0
        assert result.risk_level == "LOW"


# ── #28: --index-url flag ────────────────────────────────────────────────────

class TestIndexUrl:
    def test_index_url_flag_accepted(self):
        """--index-url must be accepted without argument parsing errors."""
        runner = CliRunner()
        with patch("pkgxray.cli.scan", return_value=_make_result(10, "LOW")):
            result = runner.invoke(
                main, ["scan", "test-pkg", "--index-url", "https://my.registry.example"]
            )
        assert result.exit_code == 0

    def test_index_url_passed_to_scan(self):
        """--index-url value must be forwarded to scan() as registry_url."""
        runner = CliRunner()
        captured = {}

        def fake_scan(package_name, version=None, *, registry_url=None):
            captured["registry_url"] = registry_url
            return _make_result(0)

        with patch("pkgxray.cli.scan", side_effect=fake_scan):
            runner.invoke(
                main, ["scan", "test-pkg", "--index-url", "https://my.registry.example"]
            )

        assert captured.get("registry_url") == "https://my.registry.example"

    def test_no_index_url_passes_none(self):
        """Without --index-url, registry_url must be None (default PyPI)."""
        runner = CliRunner()
        captured = {}

        def fake_scan(package_name, version=None, *, registry_url=None):
            captured["registry_url"] = registry_url
            return _make_result(0)

        with patch("pkgxray.cli.scan", side_effect=fake_scan):
            runner.invoke(main, ["scan", "test-pkg"])

        assert captured.get("registry_url") is None


# ── #27: clear-cache command ─────────────────────────────────────────────────

class TestClearCacheCommand:
    def test_clear_cache_command_exits_0(self):
        """pkgxray clear-cache must exit with code 0."""
        runner = CliRunner()
        with patch("pkgxray._disk_cache.clear", return_value=0):
            result = runner.invoke(main, ["clear-cache"])
        assert result.exit_code == 0

    def test_clear_cache_calls_disk_clear(self):
        """pkgxray clear-cache must invoke _disk_cache.clear()."""
        runner = CliRunner()
        with patch("pkgxray._disk_cache.clear", return_value=3) as mock_clear:
            result = runner.invoke(main, ["clear-cache"])
        mock_clear.assert_called_once()
        assert result.exit_code == 0

    def test_clear_cache_output_mentions_count(self):
        """Output must include the number of removed cache files."""
        runner = CliRunner()
        with patch("pkgxray._disk_cache.clear", return_value=5):
            result = runner.invoke(main, ["clear-cache"])
        assert "5" in result.output
