"""Tests for scorer.py — per-analyzer caps and risk level thresholds."""

import pytest

from pkgxray.analyzers.base import Finding, Severity
from pkgxray.scorer import ANALYZER_CAPS, calculate_risk_score, get_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(analyzer_name: str, severity: Severity) -> Finding:
    return Finding(
        severity=severity,
        description="test finding",
        filename="test.py",
        line_number=1,
        code_snippet="",
        analyzer_name=analyzer_name,
    )


def findings_for(analyzer_name: str, severity: Severity, count: int):
    return [make_finding(analyzer_name, severity) for _ in range(count)]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_no_findings_returns_zero_low():
    score, level = calculate_risk_score([])
    assert score == 0
    assert level == "LOW"


def test_single_low_finding():
    findings = findings_for("env_access", Severity.LOW, 1)
    score, level = calculate_risk_score(findings)
    assert score == 1
    assert level == "LOW"


# ---------------------------------------------------------------------------
# Per-analyzer caps
# ---------------------------------------------------------------------------

def test_env_access_capped_at_5():
    """50 LOW env_access findings should not exceed the env_access cap."""
    cap = ANALYZER_CAPS["env_access"]  # 5
    findings = findings_for("env_access", Severity.LOW, 50)
    score, _ = calculate_risk_score(findings)
    assert score == cap


def test_network_capped_at_8():
    """130 HIGH network findings (like requests) should be capped at 8."""
    cap = ANALYZER_CAPS["network"]  # 8
    findings = findings_for("network", Severity.HIGH, 130)
    score, _ = calculate_risk_score(findings)
    assert score == cap


def test_obfuscation_cap_is_20():
    """obfuscation cap must stay at 20 — high-confidence findings need full weight."""
    cap = ANALYZER_CAPS["obfuscation"]
    assert cap == 20


def test_setup_scripts_cap_is_20():
    """setup_scripts cap must stay at 20 — install hooks are high-confidence."""
    cap = ANALYZER_CAPS["setup_scripts"]
    assert cap == 20


def test_unknown_analyzer_uses_default_cap():
    """An analyzer not listed in ANALYZER_CAPS should use _DEFAULT_CAP."""
    from pkgxray.scorer import _DEFAULT_CAP
    findings = findings_for("future_analyzer", Severity.CRITICAL, 100)
    score, _ = calculate_risk_score(findings)
    assert score == _DEFAULT_CAP


# ---------------------------------------------------------------------------
# Threshold boundaries
# ---------------------------------------------------------------------------

def test_threshold_low_boundary():
    """Score of exactly 15 should be LOW."""
    # obfuscation weight=15 for one CRITICAL finding, cap=20 → score=15
    findings = findings_for("obfuscation", Severity.CRITICAL, 1)
    score, level = calculate_risk_score(findings)
    assert score == 15
    assert level == "LOW"


def test_threshold_moderate_lower():
    """Score of 16 should be MODERATE."""
    # obfuscation CRITICAL (15) + env_access LOW (1) = 16
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.LOW, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score == 16
    assert level == "MODERATE"


def test_threshold_moderate_upper():
    """obfuscation CRITICAL + code_exec CRITICAL triggers combo (+20); score is HIGH not MODERATE."""
    # capped: obfuscation(15) + code_exec(15) + env_access(5) = 35
    # combo obfuscation+code_exec fires (both CRITICAL ≥ HIGH): +20 → 55 → HIGH
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.CRITICAL, 10)  # capped at 5
    )
    score, level = calculate_risk_score(findings)
    assert score == 55
    assert level == "HIGH"


def test_threshold_high_lower():
    """obfuscation+code_exec combo fires; network LOW does not trigger env+network combo."""
    # capped: obfuscation(15)+code_exec(15)+env_access(5)+network(1 LOW) = 36
    # combo obfuscation+code_exec fires: +20 → 56 → HIGH
    # env_access+network does NOT fire (network max_weight=1 < HIGH threshold of 7)
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.CRITICAL, 10)
        + findings_for("network", Severity.LOW, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score == 56
    assert level == "HIGH"


def test_threshold_critical():
    """Score above 60 should be CRITICAL."""
    # obfuscation(20) + setup_scripts(20) + code_exec(15) + subprocess(12) = 67
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 2)
        + findings_for("setup_scripts", Severity.CRITICAL, 2)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("subprocess", Severity.CRITICAL, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score > 60
    assert level == "CRITICAL"


def test_global_cap_at_100():
    """Score must never exceed 100, even if per-analyzer caps sum beyond it."""
    # Each analyzer contributes its full cap. Current caps sum to 98 which is
    # already under the global ceiling, so we also add unknown analyzers to
    # push the raw total above 100 and verify the clamp holds.
    findings = []
    for analyzer_name in ANALYZER_CAPS:
        findings += findings_for(analyzer_name, Severity.CRITICAL, 20)
    # Add extra unknown analyzers to push total over 100
    for i in range(5):
        findings += findings_for(f"extra_analyzer_{i}", Severity.CRITICAL, 20)
    score, _ = calculate_risk_score(findings)
    assert score == 100


# ---------------------------------------------------------------------------
# Baseline calibration: known-clean packages (simulated findings)
# ---------------------------------------------------------------------------

def test_requests_profile_is_moderate():
    """Simulates the findings profile of 'requests': heavy network + some env + filesystem."""
    findings = (
        findings_for("network", Severity.HIGH, 130)     # HTTP calls throughout the lib
        + findings_for("env_access", Severity.LOW, 6)   # proxy env vars
        + findings_for("env_access", Severity.MEDIUM, 9)
        + findings_for("filesystem", Severity.HIGH, 4)
        + findings_for("filesystem", Severity.CRITICAL, 1)
        + findings_for("dynamic_imports", Severity.HIGH, 2)
    )
    score, level = calculate_risk_score(findings)
    assert level == "MODERATE", f"requests profile should be MODERATE, got {level} ({score})"
    assert score <= 35


def test_click_profile_is_moderate():
    """Simulates the findings profile of 'click': env reads + subprocess + filesystem."""
    findings = (
        findings_for("env_access", Severity.LOW, 13)
        + findings_for("env_access", Severity.MEDIUM, 11)
        + findings_for("filesystem", Severity.HIGH, 5)
        + findings_for("subprocess", Severity.CRITICAL, 5)
        + findings_for("subprocess", Severity.HIGH, 4)
    )
    score, level = calculate_risk_score(findings)
    assert level == "MODERATE", f"click profile should be MODERATE, got {level} ({score})"
    assert score <= 35


def test_malicious_package_profile_is_critical():
    """A package with obfuscation + install hook + module-level subprocess must be CRITICAL."""
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)    # exec(b64decode)
        + findings_for("setup_scripts", Severity.CRITICAL, 1) # install hook
        + findings_for("subprocess", Severity.CRITICAL, 1)    # module-level Popen
        + findings_for("code_exec", Severity.CRITICAL, 1)     # bare exec()
        + findings_for("network", Severity.HIGH, 1)           # exfil call
    )
    score, level = calculate_risk_score(findings)
    assert level == "CRITICAL", f"malicious profile should be CRITICAL, got {level} ({score})"


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------

def test_get_summary_counts():
    findings = (
        findings_for("network", Severity.LOW, 2)
        + findings_for("subprocess", Severity.HIGH, 1)
        + findings_for("obfuscation", Severity.CRITICAL, 1)
    )
    summary = get_summary(findings)
    assert summary["low"] == 2
    assert summary["medium"] == 0
    assert summary["high"] == 1
    assert summary["critical"] == 1
    assert summary["total"] == 4


def test_get_summary_empty():
    summary = get_summary([])
    assert summary["total"] == 0
    assert all(summary[k] == 0 for k in ["low", "medium", "high", "critical"])


# ---------------------------------------------------------------------------
# Combo bonuses
# ---------------------------------------------------------------------------

def test_combo_env_access_network_does_not_fire_at_high():
    """env_access + network both at HIGH → combo does NOT fire (requires CRITICAL).

    A legitimate AWS/Stripe SDK reads credentials from env vars inside a function
    (HIGH, not CRITICAL) and makes HTTPS calls (HIGH).  This should NOT trigger
    the credential-exfiltration combo — only module-level (CRITICAL) code auto-runs
    at import time and warrants the bonus.
    """
    base_findings = (
        findings_for("env_access", Severity.HIGH, 1)
        + findings_for("network", Severity.HIGH, 1)
    )
    score, level = calculate_risk_score(base_findings)
    # Without combo: env_access(7 → capped 5) + network(7 → min(7,8)=7) = 12
    assert score == 12
    assert level == "LOW"


def test_combo_env_access_network_fires_at_critical():
    """env_access + network both at CRITICAL → combo bonus applied.

    Module-level env reads + module-level network call = auto-executes at import.
    This is the canonical exfiltration pattern: both sides must be CRITICAL.
    """
    from pkgxray.scorer import DANGEROUS_COMBOS
    bonus = DANGEROUS_COMBOS[frozenset({"env_access", "network"})]

    base_findings = (
        findings_for("env_access", Severity.CRITICAL, 1)
        + findings_for("network", Severity.CRITICAL, 1)
    )
    score_with_combo, _ = calculate_risk_score(base_findings)

    # env_access: 15 → capped 5.  network: 15 → min(15,8) = 8.  Total capped = 13.
    # Combo fires (both CRITICAL ≥ CRITICAL threshold): +25 → 38
    assert score_with_combo == 13 + bonus


def test_combo_does_not_fire_when_severity_below_high():
    """env_access LOW + network HIGH → combo does NOT fire (env_access below threshold)."""
    base_findings = (
        findings_for("env_access", Severity.LOW, 5)   # max sev = LOW (1) < HIGH (7)
        + findings_for("network", Severity.HIGH, 1)
    )
    score, _ = calculate_risk_score(base_findings)
    # env_access capped at 5 (5*1=5), network=7 capped at 8 → total 12, no combo
    assert score == 12


def test_combo_obfuscation_code_exec_fires():
    """obfuscation CRITICAL + code_exec CRITICAL → combo of +20."""
    from pkgxray.scorer import DANGEROUS_COMBOS
    bonus = DANGEROUS_COMBOS[frozenset({"obfuscation", "code_exec"})]

    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)  # 15 → cap 20 → 15
        + findings_for("code_exec", Severity.CRITICAL, 1)  # 15 → cap 15 → 15
    )
    score, level = calculate_risk_score(findings)
    assert score == 15 + 15 + bonus  # 50
    assert level == "HIGH"


def test_combo_setup_scripts_subprocess_fires():
    """setup_scripts HIGH + subprocess HIGH → combo of +10."""
    from pkgxray.scorer import DANGEROUS_COMBOS
    bonus = DANGEROUS_COMBOS[frozenset({"setup_scripts", "subprocess"})]

    findings = (
        findings_for("setup_scripts", Severity.HIGH, 1)  # 7 → cap 20 → 7
        + findings_for("subprocess", Severity.HIGH, 1)   # 7 → cap 12 → 7
    )
    score, _ = calculate_risk_score(findings)
    assert score == 7 + 7 + bonus  # 24


def test_multiple_combos_stack():
    """When multiple combos apply simultaneously, all bonuses are added."""
    from pkgxray.scorer import DANGEROUS_COMBOS
    bonus_obf_exec = DANGEROUS_COMBOS[frozenset({"obfuscation", "code_exec"})]
    bonus_setup_sub = DANGEROUS_COMBOS[frozenset({"setup_scripts", "subprocess"})]

    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("setup_scripts", Severity.HIGH, 1)
        + findings_for("subprocess", Severity.HIGH, 1)
    )
    score, level = calculate_risk_score(findings)
    base = 15 + 15 + 7 + 7  # 44
    expected = min(100, base + bonus_obf_exec + bonus_setup_sub)
    assert score == expected
    assert level == "CRITICAL"


def test_combo_does_not_exceed_global_cap():
    """Combo bonuses cannot push the score above 100."""
    findings = []
    for name in ("obfuscation", "code_exec", "setup_scripts", "subprocess",
                 "network", "env_access", "filesystem", "dynamic_imports"):
        findings += findings_for(name, Severity.CRITICAL, 10)
    score, _ = calculate_risk_score(findings)
    assert score == 100
