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


def test_scan_result_has_binary_files_found_field():
    """ScanResult must always have binary_files_found field (defaults to 0)."""
    from pkgxray.analyzers.base import ScanResult, Finding
    from datetime import datetime, timezone
    result = ScanResult(
        package_name="test",
        version="1.0",
        scan_date=datetime.now(timezone.utc).isoformat(),
        findings=[],
        risk_score=0,
        risk_level="LOW",
        files_analyzed=0,
        summary={"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0},
    )
    assert hasattr(result, "binary_files_found")
    assert result.binary_files_found == 0


def test_count_binary_files_tarball(tmp_path):
    """_count_binary_files detects .so files inside a tarball."""
    import tarfile, io
    from pkgxray.scanner import _count_binary_files
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for name, content in [("pkg/module.py", b"x=1"), ("pkg/_ext.so", b"\x7fELF")]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    assert _count_binary_files(archive) == 1


def test_count_binary_files_zip(tmp_path):
    """_count_binary_files detects .pyd files inside a wheel."""
    import zipfile
    from pkgxray.scanner import _count_binary_files
    archive = tmp_path / "pkg.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/module.py", "x=1")
        zf.writestr("pkg/_ext.pyd", b"\x4d\x5a".decode("latin-1"))
    assert _count_binary_files(archive) == 1
