"""Tests for the persistent disk cache (_disk_cache module)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pkgxray import _disk_cache
from pkgxray.analyzers.base import Finding, ScanResult, Severity


def _make_result(
    package_name="mypkg",
    version="1.0.0",
    score=0,
    level="LOW",
    findings=None,
) -> ScanResult:
    return ScanResult(
        package_name=package_name,
        version=version,
        scan_date=datetime.now(timezone.utc).isoformat(),
        findings=findings or [],
        risk_score=score,
        risk_level=level,
        files_analyzed=3,
        summary={"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        skipped_files=[],
        binary_files_found=0,
    )


def _sha(c: str) -> str:
    return c * 64


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Redirect disk cache to an empty tmp directory for each test."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    return tmp_path


# ── Basic read / write roundtrip ─────────────────────────────────────────────

def test_write_and_read_roundtrip(isolated_cache):
    """Writing a ScanResult and reading it back must reproduce all fields."""
    result = _make_result(score=42, level="MODERATE")
    sha = _sha("a")
    _disk_cache.write(sha, result)
    loaded = _disk_cache.read(sha)

    assert loaded is not None
    assert loaded.package_name == result.package_name
    assert loaded.version == result.version
    assert loaded.risk_score == result.risk_score
    assert loaded.risk_level == result.risk_level
    assert loaded.files_analyzed == result.files_analyzed
    assert loaded.binary_files_found == result.binary_files_found
    assert loaded.summary == result.summary


def test_roundtrip_preserves_findings(isolated_cache):
    """Findings (with severity enum) survive serialization/deserialization intact."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            description="exec() call detected",
            filename="pkg/module.py",
            line_number=5,
            code_snippet="exec(user_input)",
            analyzer_name="code_exec",
        )
    ]
    result = _make_result(findings=findings, score=50, level="HIGH")
    sha = _sha("b")
    _disk_cache.write(sha, result)
    loaded = _disk_cache.read(sha)

    assert len(loaded.findings) == 1
    f = loaded.findings[0]
    assert f.severity == Severity.HIGH
    assert f.description == "exec() call detected"
    assert f.filename == "pkg/module.py"
    assert f.line_number == 5
    assert f.code_snippet == "exec(user_input)"
    assert f.analyzer_name == "code_exec"


def test_read_returns_none_for_missing(isolated_cache):
    """Reading a sha256 not in cache must return None."""
    assert _disk_cache.read(_sha("z")) is None


def test_read_returns_none_for_corrupt_json(isolated_cache):
    """A corrupt cache file must not crash — returns None."""
    cache_dir = _disk_cache.get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{_sha('c')}.json").write_text("NOT_VALID_JSON!!!{{{")
    assert _disk_cache.read(_sha("c")) is None


def test_read_returns_none_for_version_mismatch(isolated_cache):
    """Cache file with a future format version must be ignored."""
    cache_dir = _disk_cache.get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{_sha('d')}.json").write_text(
        json.dumps({"version": 9999, "package_name": "old"})
    )
    assert _disk_cache.read(_sha("d")) is None


# ── clear() ──────────────────────────────────────────────────────────────────

def test_clear_returns_0_when_empty(isolated_cache):
    """clear() on an empty (or non-existent) cache dir returns 0."""
    assert _disk_cache.clear() == 0


def test_clear_removes_all_json_files_and_returns_count(isolated_cache):
    """clear() must delete every .json file and return the exact count."""
    r1 = _make_result(package_name="pkg1")
    r2 = _make_result(package_name="pkg2")
    _disk_cache.write(_sha("e"), r1)
    _disk_cache.write(_sha("f"), r2)

    count = _disk_cache.clear()
    assert count == 2
    assert _disk_cache.read(_sha("e")) is None
    assert _disk_cache.read(_sha("f")) is None


def test_clear_leaves_non_json_files_untouched(isolated_cache):
    """clear() must only remove *.json files, not other files in the cache dir."""
    cache_dir = _disk_cache.get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    other_file = cache_dir / "lock.txt"
    other_file.write_text("lock")

    _disk_cache.write(_sha("g"), _make_result())
    _disk_cache.clear()

    assert other_file.exists(), "clear() must not remove non-.json files"


# ── get_cache_dir() ───────────────────────────────────────────────────────────

def test_get_cache_dir_returns_path(isolated_cache):
    """get_cache_dir() must always return a Path object."""
    assert isinstance(_disk_cache.get_cache_dir(), Path)


def test_get_cache_dir_uses_xdg_cache_home(tmp_path, monkeypatch):
    """XDG_CACHE_HOME env var must be respected on Linux/Mac."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    result = _disk_cache.get_cache_dir()
    assert str(result).startswith(str(tmp_path / "xdg"))
    assert result.name == "pkgxray"


# ── Disk cache integration with scan() ───────────────────────────────────────

def test_scan_writes_to_disk_cache(isolated_cache, monkeypatch):
    """scan() with a known sha256 must populate the disk cache after analysis."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod
    from pathlib import Path

    scanner_mod.clear_cache()

    sha = "a" * 64
    fake_info = {
        "info": {"version": "3.0.0"},
        "urls": [{"url": "http://x/pkg-3.0.0.tar.gz", "filename": "pkg-3.0.0.tar.gz",
                  "packagetype": "sdist", "digests": {"sha256": sha}}],
    }
    monkeypatch.setattr(dl_mod, "get_package_info", lambda *a, **kw: fake_info)
    monkeypatch.setattr(dl_mod, "download_file", lambda *a, **kw: Path("/fake/pkg.tar.gz"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    scanner_mod.scan("mypkg", version="3.0.0")

    cached = _disk_cache.read(sha)
    assert cached is not None
    assert cached.version == "3.0.0"


def test_scan_reads_from_disk_cache(isolated_cache, monkeypatch):
    """scan() must return the disk-cached result and skip download when sha matches."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.extractor as ext_mod
    import pkgxray.downloader as dl_mod

    scanner_mod.clear_cache()

    sha = "b" * 64
    cached_result = _make_result(package_name="mypkg", version="3.0.0", score=7, level="LOW")
    _disk_cache.write(sha, cached_result)

    fake_info = {
        "info": {"version": "3.0.0"},
        "urls": [{"url": "http://x/pkg-3.0.0.tar.gz", "filename": "pkg-3.0.0.tar.gz",
                  "packagetype": "sdist", "digests": {"sha256": sha}}],
    }
    download_called = {"n": 0}

    monkeypatch.setattr(dl_mod, "get_package_info", lambda *a, **kw: fake_info)
    monkeypatch.setattr(dl_mod, "download_file",
                        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("download must not be called")))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: ([], 0))

    result = scanner_mod.scan("mypkg", version="3.0.0")
    assert result.risk_score == 7
