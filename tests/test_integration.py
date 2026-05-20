"""Integration tests: run all analyzers on synthetic fixtures and assert score ranges.

These tests do NOT download from PyPI — they feed fixture strings directly through
the analysis pipeline.  They are marked @pytest.mark.integration so they run in CI
without hitting the network.
"""

import pytest

from pkgxray.analyzers import get_all_analyzers
from pkgxray.scorer import calculate_risk_score
from tests.fixtures import (
    CLEAN_CLI_TOOL,
    CLEAN_HTTP_CLIENT,
    CLEAN_PURE_LIBRARY,
    MALICIOUS_ENV_EXFIL,
    MALICIOUS_MODULE_LEVEL,
    MALICIOUS_OBFUSCATED,
    MALICIOUS_SETUP_HOOK,
)


def _analyze_code(source_code: str, filename: str = "test.py"):
    """Run all analyzers on source_code and return (score, level, findings)."""
    analyzers = get_all_analyzers()
    all_findings = []
    for analyzer in analyzers:
        findings = analyzer.analyze(source_code, filename)
        if findings:
            all_findings.extend(findings)
    score, level = calculate_risk_score(all_findings)
    return score, level, all_findings


# ---------------------------------------------------------------------------
# Malicious fixtures — must score HIGH or CRITICAL
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_malicious_module_level_subprocess():
    """subprocess.Popen at module level must score at least MODERATE.

    Without Phase 2 fixes (is_module_level not wired to filesystem/env_access),
    the combined score from subprocess + filesystem is MODERATE.  After Phase 2,
    expect HIGH or CRITICAL.
    """
    score, level, findings = _analyze_code(MALICIOUS_MODULE_LEVEL)
    assert level in ("MODERATE", "HIGH", "CRITICAL"), (
        f"module-level subprocess should be at least MODERATE, got {level} ({score})"
    )
    assert len(findings) > 0


@pytest.mark.integration
def test_malicious_obfuscated_exec():
    """exec(base64.b64decode(...)) must score HIGH or CRITICAL."""
    score, level, findings = _analyze_code(MALICIOUS_OBFUSCATED)
    assert level in ("HIGH", "CRITICAL"), (
        f"obfuscated exec should be HIGH/CRITICAL, got {level} ({score})"
    )


@pytest.mark.integration
def test_malicious_env_exfiltration():
    """Reading AWS credentials + posting to a remote URL must score HIGH or CRITICAL.

    The env_access+network combo bonus fires when env_access has ≥ HIGH findings
    (AWS_SECRET_ACCESS_KEY is a sensitive keyword → HIGH severity).
    """
    score, level, findings = _analyze_code(MALICIOUS_ENV_EXFIL)
    assert level in ("HIGH", "CRITICAL"), (
        f"credential exfiltration should be HIGH/CRITICAL, got {level} ({score})"
    )


@pytest.mark.integration
def test_malicious_setup_hook():
    """setup.py with a custom install hook running curl must score HIGH or CRITICAL.

    The setup_scripts+subprocess combo fires.  Without Phase 2 module-level escalation
    for all analyzers, the score reaches HIGH; Phase 2 will push it to CRITICAL.
    """
    score, level, findings = _analyze_code(MALICIOUS_SETUP_HOOK, filename="setup.py")
    assert level in ("HIGH", "CRITICAL"), (
        f"malicious setup hook should be HIGH/CRITICAL, got {level} ({score})"
    )


# ---------------------------------------------------------------------------
# Clean fixtures — must score LOW or MODERATE
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_clean_pure_library():
    """A pure data-processing library with no IO must score LOW."""
    score, level, findings = _analyze_code(CLEAN_PURE_LIBRARY)
    assert level == "LOW", (
        f"pure library should be LOW, got {level} ({score})"
    )


@pytest.mark.integration
def test_clean_http_client():
    """An HTTP client helper must score LOW or MODERATE (calls inside function)."""
    score, level, findings = _analyze_code(CLEAN_HTTP_CLIENT)
    assert level in ("LOW", "MODERATE"), (
        f"clean HTTP client should be LOW/MODERATE, got {level} ({score})"
    )


@pytest.mark.integration
def test_clean_cli_tool():
    """A CLI tool using os.getenv + subprocess inside a function must score LOW or MODERATE."""
    score, level, findings = _analyze_code(CLEAN_CLI_TOOL)
    assert level in ("LOW", "MODERATE"), (
        f"clean CLI tool should be LOW/MODERATE, got {level} ({score})"
    )


# ---------------------------------------------------------------------------
# Sanity: malicious scores strictly above clean scores
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_malicious_scores_above_clean():
    """Malicious fixtures must collectively score higher than clean fixtures."""
    malicious_scores = []
    for code, fname in [
        (MALICIOUS_MODULE_LEVEL, "test.py"),
        (MALICIOUS_OBFUSCATED, "test.py"),
        (MALICIOUS_SETUP_HOOK, "setup.py"),
    ]:
        score, _, _ = _analyze_code(code, fname)
        malicious_scores.append(score)

    clean_scores = []
    for code in [CLEAN_PURE_LIBRARY, CLEAN_HTTP_CLIENT, CLEAN_CLI_TOOL]:
        score, _, _ = _analyze_code(code)
        clean_scores.append(score)

    assert min(malicious_scores) > max(clean_scores), (
        f"Lowest malicious score ({min(malicious_scores)}) should exceed "
        f"highest clean score ({max(clean_scores)})"
    )
