"""Tests for reporter.py — output format correctness and XSS regression."""

import json

import pytest

from pkgxray.analyzers.base import Finding, ScanResult, Severity
from pkgxray.reporter import generate_html_report, generate_json_report, print_terminal_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(findings=None, skipped_files=None, package_name="test-pkg", version="1.0.0"):
    findings = findings or []
    skipped_files = skipped_files or []
    return ScanResult(
        package_name=package_name,
        version=version,
        scan_date="2025-01-01T00:00:00+00:00",
        findings=findings,
        risk_score=0,
        risk_level="LOW",
        files_analyzed=1,
        summary={"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0},
        skipped_files=skipped_files,
    )


def _make_finding(
    description="test finding",
    filename="module.py",
    analyzer_name="network",
    severity=Severity.HIGH,
    code_snippet="requests.get(url)",
    line_number=42,
):
    return Finding(
        severity=severity,
        description=description,
        filename=filename,
        line_number=line_number,
        code_snippet=code_snippet,
        analyzer_name=analyzer_name,
    )


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def test_json_report_is_valid_json():
    result = _make_result()
    output = generate_json_report(result)
    data = json.loads(output)
    assert isinstance(data, dict)


def test_json_report_has_required_fields():
    result = _make_result()
    data = json.loads(generate_json_report(result))
    for field in ("package_name", "version", "risk_score", "risk_level",
                  "files_analyzed", "findings", "summary",
                  "files_skipped", "skipped_files"):
        assert field in data, f"Missing field: {field}"


def test_json_report_findings_serialized():
    finding = _make_finding()
    result = _make_result(findings=[finding])
    data = json.loads(generate_json_report(result))
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["severity"] == "high"
    assert f["description"] == "test finding"
    assert f["filename"] == "module.py"
    assert f["analyzer_name"] == "network"
    assert f["line_number"] == 42


def test_json_report_skipped_files_included():
    skipped = [{"filename": "broken.py", "reason": "syntax_error"}]
    result = _make_result(skipped_files=skipped)
    data = json.loads(generate_json_report(result))
    assert data["files_skipped"] == 1
    assert data["skipped_files"][0]["filename"] == "broken.py"


# ---------------------------------------------------------------------------
# HTML report — structure
# ---------------------------------------------------------------------------

def test_html_report_returns_string():
    result = _make_result()
    html = generate_html_report(result)
    assert isinstance(html, str)
    assert "<!DOCTYPE html>" in html


def test_html_report_contains_package_name():
    result = _make_result(package_name="mypkg")
    html = generate_html_report(result)
    assert "mypkg" in html


def test_html_report_no_findings_shows_message():
    result = _make_result()
    html = generate_html_report(result)
    assert "No se encontraron" in html


def test_html_report_with_findings_shows_table():
    finding = _make_finding()
    result = _make_result(findings=[finding])
    html = generate_html_report(result)
    assert "<table>" in html
    assert "module.py" in html


# ---------------------------------------------------------------------------
# HTML report — XSS regression (BUG-01)
# ---------------------------------------------------------------------------

def test_html_escapes_description():
    """A finding description with HTML tags must be escaped, not rendered."""
    finding = _make_finding(description='<script>alert("xss")</script>')
    result = _make_result(findings=[finding])
    output = generate_html_report(result)
    assert '<script>' not in output
    assert '&lt;script&gt;' in output


def test_html_escapes_filename():
    """A filename containing HTML tags must be escaped."""
    finding = _make_finding(filename='<img src=x onerror=alert(1)>.py')
    result = _make_result(findings=[finding])
    output = generate_html_report(result)
    assert '<img' not in output
    assert '&lt;img' in output


def test_html_escapes_analyzer_name():
    """analyzer_name is user-controlled (from the package) and must be escaped."""
    finding = _make_finding(analyzer_name='<b>bold</b>')
    result = _make_result(findings=[finding])
    output = generate_html_report(result)
    assert '<b>' not in output
    assert '&lt;b&gt;' in output


def test_html_escapes_code_snippet():
    """code_snippet with HTML must not render as markup."""
    finding = _make_finding(code_snippet='exec("<script>evil()</script>")')
    result = _make_result(findings=[finding])
    output = generate_html_report(result)
    assert '<script>' not in output
    assert '&lt;script&gt;' in output


def test_html_escapes_package_name_in_header():
    """Package name from PyPI could theoretically contain HTML — must be escaped."""
    result = _make_result(package_name='<script>alert(1)</script>')
    output = generate_html_report(result)
    assert '<script>' not in output
    assert '&lt;script&gt;' in output


def test_html_escapes_skipped_filename_in_warning():
    """Skipped file names in the warning section must be escaped."""
    skipped = [{"filename": '<script>alert(1)</script>.py', "reason": "syntax_error"}]
    result = _make_result(skipped_files=skipped)
    output = generate_html_report(result)
    assert '<script>' not in output
    assert '&lt;script&gt;' in output


def test_html_ampersand_and_quotes_escaped():
    """Ampersands and quotes in user-controlled fields must be escaped."""
    finding = _make_finding(description='test & "quotes" and \'apostrophe\'')
    result = _make_result(findings=[finding])
    output = generate_html_report(result)
    assert '&amp;' in output


# ---------------------------------------------------------------------------
# Terminal report — smoke tests (no crash)
# ---------------------------------------------------------------------------

def test_terminal_report_no_crash_empty(capsys):
    result = _make_result()
    print_terminal_report(result)


def test_terminal_report_no_crash_with_findings(capsys):
    finding = _make_finding()
    result = _make_result(findings=[finding])
    print_terminal_report(result)


def test_terminal_report_no_crash_with_skipped(capsys):
    skipped = [{"filename": "broken.py", "reason": "syntax_error"}]
    result = _make_result(skipped_files=skipped)
    print_terminal_report(result)


# ---------------------------------------------------------------------------
# generate_report — output_format parameter (regression: was named 'format')
# ---------------------------------------------------------------------------

def test_generate_report_json_output_format():
    """`generate_report` must accept `output_format` keyword (not `format`)."""
    from pkgxray.reporter import generate_report
    result = _make_result()
    output = generate_report(result, output_format="json")
    assert output is not None
    import json
    data = json.loads(output)
    assert data["package_name"] == "test-pkg"


def test_generate_report_html_output_format():
    from pkgxray.reporter import generate_report
    result = _make_result()
    output = generate_report(result, output_format="html")
    assert output is not None
    assert "pkgxray" in output


def test_generate_report_invalid_format_raises():
    from pkgxray.reporter import generate_report
    result = _make_result()
    with pytest.raises(ValueError, match="Formato desconocido"):
        generate_report(result, output_format="xml")
