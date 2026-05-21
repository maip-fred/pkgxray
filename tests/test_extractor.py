"""Tests for the archive extractor."""

import io
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from pkgxray.extractor import extract_python_files, _is_python_file, _is_setup_file, _is_config_file, _is_binary_file


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
        files, _ = extract_python_files(archive)
        names = [f.filename for f in files]
        assert any("module.py" in n for n in names)
        assert any("setup.py" in n for n in names)
    finally:
        archive.unlink()


def test_setup_py_flagged():
    archive = _make_tarball({"pkg/setup.py": "from setuptools import setup\nsetup()"})
    try:
        files, _ = extract_python_files(archive)
        setup_files = [f for f in files if f.is_setup]
        assert len(setup_files) >= 1
    finally:
        archive.unlink()


def test_extract_from_zip():
    archive = _make_zip({
        "mypackage/module.py": "x = 1",
    })
    try:
        files, _ = extract_python_files(archive)
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
    """is_setup es True solo para setup.py — activa SetupScriptAnalyzer."""
    assert _is_setup_file("setup.py")
    assert _is_setup_file("pkg/setup.py")
    assert not _is_setup_file("setup.cfg")    # setup.cfg → ConfigFileAnalyzer
    assert not _is_setup_file("pyproject.toml")
    assert not _is_setup_file("module.py")


def test_is_config_file():
    """is_config es True para pyproject.toml y setup.cfg — activa ConfigFileAnalyzer."""
    assert _is_config_file("pyproject.toml")
    assert _is_config_file("setup.cfg")
    assert _is_config_file("pkg/pyproject.toml")
    assert not _is_config_file("setup.py")
    assert not _is_config_file("module.py")


def test_path_traversal_skipped():
    archive = _make_tarball({"../../etc/passwd": "root:x:0:0"})
    try:
        files, _ = extract_python_files(archive)
        # Should not extract files with .. in path
        assert len(files) == 0
    finally:
        archive.unlink()


def test_path_traversal_normpath_bypass_tarball():
    """foo/./../../evil.py usa normpath-bypass pero debe ser rechazado."""
    archive = _make_tarball({"foo/./../../evil.py": "import os; os.system('id')"})
    try:
        files, _ = extract_python_files(archive)
        assert len(files) == 0
    finally:
        archive.unlink()


def test_path_traversal_normpath_bypass_zip():
    """La misma variante de bypass en un .zip también debe ser rechazada."""
    archive = _make_zip({"foo/./../../evil.py": "import os"})
    try:
        files, _ = extract_python_files(archive)
        assert len(files) == 0
    finally:
        archive.unlink()


def test_absolute_path_skipped_tarball():
    """Las rutas absolutas en tarballs deben ser rechazadas."""
    archive = _make_tarball({"/etc/evil.py": "malicious"})
    try:
        files, _ = extract_python_files(archive)
        assert len(files) == 0
    finally:
        archive.unlink()


def test_windows_backslash_traversal_rejected_tarball(tmp_path):
    """foo\\..\\..\\evil.py must be rejected even on Linux."""
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        content = b"evil = True\n"
        info = tarfile.TarInfo(name="foo\\..\\..\\evil.py")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    result, _ = extract_python_files(archive)
    assert result == [], "Windows-style traversal must be rejected"


def test_windows_backslash_traversal_rejected_zip(tmp_path):
    """foo\\..\\..\\evil.py must be rejected even on Linux (zip)."""
    archive = tmp_path / "pkg.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("foo\\..\\..\\evil.py")
        zf.writestr(info, "evil = True\n")
    result, _ = extract_python_files(archive)
    assert result == [], "Windows-style traversal must be rejected"


def test_is_binary_file():
    """_is_binary_file() must recognise common compiled extension suffixes."""
    assert _is_binary_file("module.so")
    assert _is_binary_file("lib/module.pyd")
    assert _is_binary_file("lib.dll")
    assert _is_binary_file("lib.dylib")
    assert not _is_binary_file("module.py")
    assert not _is_binary_file("setup.cfg")


def test_binary_files_not_extracted(tmp_path):
    """Binary files (.so) inside an archive must not appear in extracted output."""
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for name, content in [("pkg/module.py", b"x = 1"), ("pkg/_ext.so", b"\x7fELF")]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    result, binary_count = extract_python_files(archive)
    filenames = [f.filename for f in result]
    assert any("module.py" in fn for fn in filenames)
    assert not any(fn.endswith(".so") for fn in filenames)
    assert binary_count == 1


# ── #24: previously uncovered branches ───────────────────────────────────────

def test_corrupted_tarball_does_not_crash(tmp_path):
    """A corrupted .tar.gz must return empty list, not raise."""
    archive = tmp_path / "corrupt.tar.gz"
    archive.write_bytes(b"not a real tarball at all!!!")
    result, binary_count = extract_python_files(archive)
    assert result == []
    assert binary_count == 0


def test_corrupted_zip_does_not_crash(tmp_path):
    """A corrupted .zip must return empty list, not raise."""
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"this is not a zip file")
    result, binary_count = extract_python_files(archive)
    assert result == []
    assert binary_count == 0


def test_is_config_flag_set_on_pyproject_toml():
    """Extracted pyproject.toml must have is_config=True."""
    archive = _make_tarball({"pkg/pyproject.toml": '[build-system]\nrequires = ["setuptools"]'})
    try:
        files, _ = extract_python_files(archive)
        config_files = [f for f in files if f.is_config]
        assert len(config_files) >= 1
        assert any("pyproject.toml" in f.filename for f in config_files)
    finally:
        archive.unlink()


def test_is_config_flag_set_on_setup_cfg():
    """Extracted setup.cfg must have is_config=True."""
    archive = _make_tarball({"pkg/setup.cfg": "[metadata]\nname = mypkg\n"})
    try:
        files, _ = extract_python_files(archive)
        config_files = [f for f in files if f.is_config]
        assert len(config_files) >= 1
    finally:
        archive.unlink()


def test_unsupported_format_raises():
    """Unsupported archive format should raise ValueError."""
    archive = _make_tarball({"pkg/module.py": "x = 1"})
    try:
        import shutil
        bad = Path(str(archive).replace(".tar.gz", ".rar"))
        shutil.copy(archive, bad)
        with pytest.raises(ValueError, match="no soportado"):
            extract_python_files(bad)
        bad.unlink()
    finally:
        archive.unlink()
