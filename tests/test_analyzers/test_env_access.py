"""Tests for EnvAccessAnalyzer."""

from pkgxray.analyzers.env_access import EnvAccessAnalyzer
from pkgxray.analyzers.base import Severity


def test_detects_os_environ_subscript():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.environ["HOME"]', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_detects_os_getenv():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("PATH")', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_detects_os_environ_get():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.environ.get("DEBUG", "false")', 'test.py')
    assert len(findings) >= 1
    # Variable no sensible → LOW
    assert all(f.severity == Severity.LOW for f in findings)


def test_sensitive_variable_upgrades_severity():
    """Variable sensible al nivel del módulo → CRITICAL (escalado)."""
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("AWS_SECRET_KEY")', 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_sensitive_variable_in_function():
    """Variable sensible dentro de función → HIGH (no escalado)."""
    analyzer = EnvAccessAnalyzer()
    code = 'def connect():\n    import os\n    val = os.getenv("AWS_SECRET_KEY")'
    findings = analyzer.analyze(code, 'test.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_sensitive_token_upgrades_severity():
    """Variable con TOKEN al nivel del módulo → CRITICAL (escalado)."""
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nkey = os.environ["API_TOKEN"]', 'test.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_non_sensitive_at_module_level_stays_low():
    """Variable no sensible al nivel del módulo → LOW (no se escala)."""
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("HOME")', 'test.py')
    assert all(f.severity == Severity.LOW for f in findings)


def test_safe_code_no_findings():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('x = 1 + 2\nprint(x)', 'test.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'test.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = EnvAccessAnalyzer()
    findings = analyzer.analyze('import os\nval = os.getenv("X")', 'test.py')
    assert all(f.analyzer_name == "env_access" for f in findings)


# ── P2-06: keywords expandidos ────────────────────────────────────────────────

def test_github_token_is_sensitive():
    """GITHUB_TOKEN debe ser HIGH (contiene 'TOKEN')."""
    analyzer = EnvAccessAnalyzer()
    code = 'def push():\n    import os\n    t = os.getenv("GITHUB_TOKEN")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


def test_anthropic_api_key_is_sensitive():
    """ANTHROPIC_API_KEY debe ser HIGH (contiene 'API_KEY')."""
    analyzer = EnvAccessAnalyzer()
    code = 'def call_ai():\n    import os\n    k = os.getenv("ANTHROPIC_API_KEY")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


def test_stripe_key_is_sensitive():
    """STRIPE_KEY debe ser HIGH (contiene 'STRIPE_KEY')."""
    analyzer = EnvAccessAnalyzer()
    code = 'def charge():\n    import os\n    k = os.getenv("STRIPE_KEY")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.HIGH for f in findings)


# ── P2-04: ClassDef no es barrera ────────────────────────────────────────────

def test_class_body_env_access_escalated():
    """os.getenv(SECRET) en cuerpo de clase → CRITICAL (corre al importar)."""
    analyzer = EnvAccessAnalyzer()
    code = 'class Config:\n    key = os.getenv("AWS_SECRET_ACCESS_KEY")'
    findings = analyzer.analyze(code, 'test.py')
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_getenv_on_non_os_object_not_flagged():
    """config.getenv(), parser.getenv() etc. must NOT be flagged."""
    analyzer = EnvAccessAnalyzer()
    code = (
        "class Config:\n"
        "    def getenv(self, key): return None\n"
        "cfg = Config()\n"
        "val = cfg.getenv('SECRET_KEY')\n"
    )
    findings = analyzer.analyze(code, "test.py")
    assert findings == [], f"Unexpected findings: {findings}"


def test_os_getenv_still_flagged():
    """os.getenv() must still be detected after the receiver check is added."""
    analyzer = EnvAccessAnalyzer()
    # Module-level os.getenv() with a sensitive key escalates to CRITICAL
    code = "import os\ntoken = os.getenv('API_KEY')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) == 1
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_parser_getenv_not_flagged():
    """parser.getenv() must not generate a finding."""
    analyzer = EnvAccessAnalyzer()
    code = "value = parser.getenv('DATABASE_URL')\n"
    findings = analyzer.analyze(code, "test.py")
    assert findings == []


# ── #8: aliased os module ────────────────────────────────────────────────────

def test_aliased_os_environ_subscript_detected():
    """import os as operating_system; operating_system.environ['AWS_KEY'] must be detected."""
    analyzer = EnvAccessAnalyzer()
    code = "import os as operating_system\nsecret = operating_system.environ['AWS_SECRET_ACCESS_KEY']\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased os.environ subscript must be detected"


def test_aliased_os_getenv_detected():
    """import os as o; o.getenv('TOKEN') must be detected."""
    analyzer = EnvAccessAnalyzer()
    code = "import os as o\nval = o.getenv('GITHUB_TOKEN')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased os.getenv must be detected"


def test_aliased_os_environ_get_detected():
    """import os as o; o.environ.get('SECRET') must be detected."""
    analyzer = EnvAccessAnalyzer()
    code = "import os as o\nval = o.environ.get('AWS_ACCESS_KEY')\n"
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1, "Aliased os.environ.get must be detected"
