"""Tests for the archive extractor."""

import io
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from pkgxray.extractor import extract_python_files, _is_python_file, _is_setup_file


def _make_tarball(files: dict) -> Path:
    """Create a temporary .tar.gz with the given files {name: content}."""
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    with tarfile.open(tmp.name, "w:gz") as tf:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return Path(tmp.name)


def _make_zip(files: dict) -> Path:
    """Create a temporary .zip with the given files."""
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    with zipfile.ZipFile(tmp.name, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return Path(tmp.name)


def test_extract_from_tarball():
    archive = _make_tarball({
        "mypackage/module.py": "x = 1",
        "mypackage/setup.py": "from setuptools import setup\nsetup()",
    })
    try:
        files = extract_python_files(archive)
        names = [f.filename for f in files]
        assert any("module.py" in n for n in names)
        assert any("setup.py" in n for n in names)
    finally:
        archive.unlink()


def test_setup_py_flagged():
    archive = _make_tarball({"pkg/setup.py": "from setuptools import setup\nsetup()"})
    try:
        files = extract_python_files(archive)
        setup_files = [f for f in files if f.is_setup]
        assert len(setup_files) >= 1
    finally:
        archive.unlink()


def test_extract_from_zip():
    archive = _make_zip({
        "mypackage/module.py": "x = 1",
    })
    try:
        files = extract_python_files(archive)
        assert len(files) >= 1
    finally:
        archive.unlink()


def test_unsupported_format_raises():
    tmp = tempfile.NamedTemporaryFile(suffix=".rar", delete=False)
    tmp.close()
    try:
        with pytest.raises(ValueError, match="Formato de archivo no soportado"):
            extract_python_files(Path(tmp.name))
    finally:
        Path(tmp.name).unlink()


def test_is_python_file():
    assert _is_python_file("module.py")
    assert _is_python_file("setup.cfg")
    assert _is_python_file("pyproject.toml")
    assert not _is_python_file("README.md")
    assert not _is_python_file("image.png")


def test_is_setup_file():
    assert _is_setup_file("setup.py")
    assert _is_setup_file("setup.cfg")
    assert not _is_setup_file("pyproject.toml")
    assert not _is_setup_file("module.py")


def test_path_traversal_skipped():
    archive = _make_tarball({"../../etc/passwd": "root:x:0:0"})
    try:
        files = extract_python_files(archive)
        # Should not extract files with .. in path
        assert len(files) == 0
    finally:
        archive.unlink()
