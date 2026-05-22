"""Tests for the PyPI downloader."""

import pytest
from pkgxray.downloader import (
    get_package_info,
    find_best_distribution,
    download_package,
    download_file,
    PackageNotFoundError,
    DownloadError,
)


def test_get_package_info_valid():
    """Test fetching metadata for a known package."""
    info = get_package_info("requests")
    assert "info" in info
    assert info["info"]["name"].lower() == "requests"


def test_get_package_info_invalid():
    """Test that an unknown package raises PackageNotFoundError."""
    with pytest.raises(PackageNotFoundError):
        get_package_info("paquete-que-no-existe-xyz123abc987")


def test_find_best_distribution():
    """Test that find_best_distribution returns URL, filename, and optional sha256."""
    info = get_package_info("requests")
    url, filename, sha256 = find_best_distribution(info)
    assert url.startswith("https://")
    assert len(filename) > 0
    # PyPI always provides sha256 digests; sha256 may be None for legacy entries
    assert sha256 is None or len(sha256) == 64


def test_find_best_distribution_no_urls():
    """Test that DownloadError is raised when no URLs are available."""
    fake_info = {"urls": [], "info": {"version": "1.0.0"}}
    with pytest.raises(DownloadError):
        find_best_distribution(fake_info)


def test_find_best_distribution_prefers_sdist():
    """sdist entry should be preferred over wheel."""
    fake_info = {
        "urls": [
            {"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl", "url": "https://a/whl", "digests": {}},
            {"packagetype": "sdist", "filename": "pkg-1.0.tar.gz", "url": "https://a/tar", "digests": {"sha256": "abc123"}},
        ],
        "info": {"version": "1.0"},
    }
    url, filename, sha256 = find_best_distribution(fake_info)
    assert filename.endswith(".tar.gz")
    assert sha256 == "abc123"


# ── #23: error path coverage ─────────────────────────────────────────────────

def test_get_package_info_http_error_non_404():
    """Non-404 HTTP errors should raise DownloadError."""
    from unittest.mock import patch, MagicMock
    import urllib.error
    mock_resp = MagicMock()
    mock_resp.code = 500
    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        url="https://pypi.org", code=500, msg="Server Error", hdrs=None, fp=None
    )):
        with pytest.raises(DownloadError, match="500"):
            get_package_info("anypackage")


def test_get_package_info_url_error():
    """Network errors should raise DownloadError."""
    from unittest.mock import patch
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
        with pytest.raises(DownloadError):
            get_package_info("anypackage")


def test_get_package_info_json_parse_error():
    """Malformed JSON response should raise DownloadError."""
    from unittest.mock import patch, MagicMock
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = b"not-valid-json{{{{"
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(DownloadError):
            get_package_info("anypackage")


def test_download_package_returns_path():
    """Test that download_package returns a valid path."""
    import tempfile
    import os
    with tempfile.TemporaryDirectory() as tmp:
        path, version = download_package("requests", dest_dir=tmp)
        assert path.exists()
        assert len(version) > 0


# ── #28: private registry / registry_url support ──────────────────────────────

def test_get_package_info_uses_registry_url():
    """get_package_info() must build the URL from the registry_url argument."""
    from unittest.mock import patch, MagicMock
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"info": {"version": "1.0"}, "urls": []}'
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        get_package_info("mypkg", registry_url="https://my.registry.example")

    assert "my.registry.example" in captured["url"]
    assert "mypkg" in captured["url"]


def test_get_package_info_uses_env_var(monkeypatch):
    """PKGXRAY_INDEX_URL env var must override the default PyPI URL."""
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("PKGXRAY_INDEX_URL", "https://env.registry.test")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"info": {"version": "1.0"}, "urls": []}'
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        get_package_info("mypkg")

    assert "env.registry.test" in captured["url"]


def test_get_package_info_explicit_url_overrides_env(monkeypatch):
    """Explicit registry_url must take precedence over PKGXRAY_INDEX_URL env var."""
    from unittest.mock import patch, MagicMock
    monkeypatch.setenv("PKGXRAY_INDEX_URL", "https://env.registry.test")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"info": {"version": "1.0"}, "urls": []}'
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        get_package_info("mypkg", registry_url="https://explicit.registry.test")

    assert "explicit.registry.test" in captured["url"]
    assert "env.registry.test" not in captured["url"]


def test_download_file_returns_path_and_verifies_sha256(tmp_path):
    """download_file() must write the file and pass SHA-256 verification."""
    import hashlib
    from unittest.mock import patch, MagicMock

    content = b"fake archive content"
    sha256 = hashlib.sha256(content).hexdigest()

    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = content

    with patch("urllib.request.urlopen", return_value=mock_resp):
        path = download_file("http://x/pkg-1.0.tar.gz", sha256, "pkg-1.0.tar.gz", str(tmp_path))

    assert path.exists()
    assert path.read_bytes() == content


def test_download_file_raises_on_sha256_mismatch(tmp_path):
    """download_file() must raise DownloadError when SHA-256 doesn't match."""
    from unittest.mock import patch, MagicMock

    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = b"wrong content"

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(DownloadError, match="SHA-256"):
            download_file("http://x/pkg.tar.gz", "a" * 64, "pkg.tar.gz", str(tmp_path))


# ── Phase 8 D1 tests ─────────────────────────────────────────────────────────

import urllib.error
from unittest.mock import patch, MagicMock


def test_get_package_info_http_error_non_404_raises_download_error():
    """HTTP errors other than 404 must raise DownloadError, not PackageNotFoundError."""
    error = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs={}, fp=None)
    with patch("urllib.request.urlopen", side_effect=error):
        try:
            get_package_info("requests")
            assert False, "Expected DownloadError"
        except DownloadError as e:
            assert "500" in str(e)


def test_get_package_info_url_error_raises_download_error():
    """URLError (network failure) must raise DownloadError."""
    error = urllib.error.URLError(reason="Name or service not known")
    with patch("urllib.request.urlopen", side_effect=error):
        try:
            get_package_info("requests")
            assert False, "Expected DownloadError"
        except DownloadError as e:
            assert "red" in str(e).lower() or "url" in str(e).lower()


def test_get_package_info_json_error_raises_download_error():
    """Invalid JSON response must raise DownloadError."""
    mock_response = MagicMock()
    mock_response.read.return_value = b"not valid json {{{"
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_response):
        try:
            get_package_info("requests")
            assert False, "Expected DownloadError"
        except DownloadError:
            pass


def test_find_best_distribution_falls_back_to_any_wheel():
    """find_best_distribution must fall back to any-wheel if no sdist."""
    package_info = {"urls": [
        {"url": "https://example.com/pkg-1.0-cp312-cp312-linux.whl",
         "filename": "pkg-1.0-cp312-cp312-linux.whl", "packagetype": "bdist_wheel",
         "digests": {}},
        {"url": "https://example.com/pkg-1.0-py3-none-any.whl",
         "filename": "pkg-1.0-py3-none-any.whl", "packagetype": "bdist_wheel",
         "digests": {}},
    ]}
    url, filename, sha256 = find_best_distribution(package_info)
    assert "any" in filename


def test_find_best_distribution_no_urls_raises_download_error():
    """Empty urls list must raise DownloadError."""
    try:
        find_best_distribution({"urls": []})
        assert False, "Expected DownloadError"
    except DownloadError:
        pass
