"""Tests for the PyPI downloader."""

import pytest
from pkgxray.downloader import (
    get_package_info,
    find_best_distribution,
    download_package,
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
    """Test that find_best_distribution returns a URL and filename."""
    info = get_package_info("requests")
    url, filename = find_best_distribution(info)
    assert url.startswith("https://")
    assert len(filename) > 0


def test_find_best_distribution_no_urls():
    """Test that DownloadError is raised when no URLs are available."""
    fake_info = {"urls": [], "info": {"version": "1.0.0"}}
    with pytest.raises(DownloadError):
        find_best_distribution(fake_info)


def test_download_package_returns_path():
    """Test that download_package returns a valid path."""
    import tempfile
    import os
    with tempfile.TemporaryDirectory() as tmp:
        path, version = download_package("requests", dest_dir=tmp)
        assert path.exists()
        assert len(version) > 0
