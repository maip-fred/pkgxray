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


def test_cache_returns_same_object_for_pinned_version(monkeypatch):
    """scan() with a pinned version must hit the cache on the second call (no re-download)."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod

    scanner_mod.clear_cache()

    call_count = {"n": 0}

    def fake_download(*a, **kw):
        call_count["n"] += 1
        return ("/fake/pkg.tar.gz", "1.2.3")

    monkeypatch.setattr(dl_mod, "download_package", fake_download)
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    result1 = scanner_mod.scan("mypkg", version="1.2.3")
    result2 = scanner_mod.scan("mypkg", version="1.2.3")

    assert call_count["n"] == 1, "Second call must hit cache — download called only once"
    assert result1.package_name == result2.package_name
    assert result1.version == result2.version


def test_cache_not_used_for_latest_version(monkeypatch):
    """scan() without a pinned version must never read or write the cache."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod

    scanner_mod.clear_cache()

    call_count = {"n": 0}

    def fake_download(*a, **kw):
        call_count["n"] += 1
        return ("/fake/pkg.tar.gz", "1.2.3")

    monkeypatch.setattr(dl_mod, "download_package", fake_download)
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    scanner_mod.scan("mypkg")
    scanner_mod.scan("mypkg")

    assert call_count["n"] == 2, "Latest-version scans must not be cached"


def test_clear_cache_invalidates_stored_result(monkeypatch):
    """clear_cache() must force a fresh scan on the next call."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod

    scanner_mod.clear_cache()

    monkeypatch.setattr(dl_mod, "download_package",
                        lambda *a, **kw: ("/fake/pkg.tar.gz", "2.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    result1 = scanner_mod.scan("mypkg", version="2.0.0")
    scanner_mod.clear_cache()
    result2 = scanner_mod.scan("mypkg", version="2.0.0")

    assert result1 is not result2, "After clear_cache(), a new object must be returned"


def test_cache_is_case_insensitive_on_package_name(monkeypatch):
    """Cache key must normalise package name to lowercase."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod

    scanner_mod.clear_cache()

    call_count = {"n": 0}

    def counting_download(*a, **kw):
        call_count["n"] += 1
        return ("/fake/pkg.tar.gz", "1.0.0")

    monkeypatch.setattr(dl_mod, "download_package", counting_download)
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    result1 = scanner_mod.scan("MyPkg", version="1.0.0")
    result2 = scanner_mod.scan("mypkg", version="1.0.0")

    assert call_count["n"] == 1, "Case-insensitive cache must avoid re-download"
    assert result1.version == result2.version


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


def test_extract_python_files_counts_binary_tarball(tmp_path):
    """extract_python_files() returns binary count in second tuple element."""
    import io, tarfile
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="mylib/fast.so")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"\x7fELF"))
        py_info = tarfile.TarInfo(name="mylib/__init__.py")
        py_content = b"x = 1\n"
        py_info.size = len(py_content)
        tf.addfile(py_info, io.BytesIO(py_content))
    from pkgxray.extractor import extract_python_files
    files, binary_count = extract_python_files(archive)
    assert binary_count == 1
    assert len(files) == 1


def test_extract_python_files_counts_binary_zip(tmp_path):
    """extract_python_files() returns binary count for .whl archives."""
    import zipfile
    archive = tmp_path / "pkg.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("mylib/fast.pyd", b"\x4d\x5a")
        zf.writestr("mylib/__init__.py", "x = 1\n")
    from pkgxray.extractor import extract_python_files
    files, binary_count = extract_python_files(archive)
    assert binary_count == 1
    assert len(files) == 1
