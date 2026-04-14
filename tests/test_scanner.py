"""Tests for the main scanner."""

import pytest
from pkgxray.scanner import scan
from pkgxray.analyzers.base import ScanResult
from pkgxray.downloader import PackageNotFoundError


@pytest.mark.slow
def test_scan_known_package():
    """Scan a well-known package and verify the result structure."""
    result = scan("requests")
    assert isinstance(result, ScanResult)
    assert result.package_name == "requests"
    assert len(result.version) > 0
    assert isinstance(result.risk_score, int)
    assert 0 <= result.risk_score <= 100
    assert result.risk_level in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert result.files_analyzed > 0


@pytest.mark.slow
def test_scan_result_structure():
    """Verify that all ScanResult fields are present and correctly typed."""
    result = scan("requests")
    assert hasattr(result, "package_name")
    assert hasattr(result, "version")
    assert hasattr(result, "scan_date")
    assert hasattr(result, "findings")
    assert hasattr(result, "risk_score")
    assert hasattr(result, "risk_level")
    assert hasattr(result, "files_analyzed")
    assert hasattr(result, "summary")
    assert isinstance(result.findings, list)
    assert isinstance(result.summary, dict)
    assert "total" in result.summary


def test_scan_unknown_package_raises():
    """Scanning a non-existent package should raise PackageNotFoundError."""
    with pytest.raises(PackageNotFoundError):
        scan("paquete-que-no-existe-xyz123abc987")
