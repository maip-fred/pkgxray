# pkgxray — Project Quanta

Every building block (quantum) of pkgxray: what it is, what it does, its current state, and what needs attention.

**Version:** 0.3.0-dev (P1 + P2 complete)

---

## Pipeline at a Glance

```
User / CLI
    |
    v
scanner.scan()              <- single public entry-point
    |
    +-> downloader           <- fetches metadata + archive from PyPI (no install)
    |       |
    |       +-> extractor    <- opens .tar.gz / .whl; yields ExtractedFile objects
    |               |
    |               +-> analyzers (x8)   <- AST-based detection per file
    |                       |
    |                       +-> scorer   <- weights + caps -> risk_score 0-100
    |
    +-> ScanResult           <- returned to caller
            |
            +-> reporter     <- terminal (rich), JSON, or HTML
```

---

## Core Modules

### `scanner.py` — Pipeline Orchestrator

**What it does:** The single `scan(package_name, version=None)` function that drives the entire pipeline. Creates a temp dir, calls each stage in order, tears down the temp dir in a `finally` block.

**Key behaviours:**
- Analyser isolation: a crash in any `analyzer.analyze()` call never aborts the scan
- `SetupScriptAnalyzer` is short-circuited for non-`setup.py` files (double-gated with the analyser itself)
- Returns a `ScanResult` with the concrete version scanned, not just "latest"

**Raises:** `PackageNotFoundError`, `DownloadError`

**✅ [P4-04]:** Los fallos individuales de analizadores ahora emiten `logger.warning(...)` en lugar de silenciarse completamente. Usuarios pueden activar logs con `logging.basicConfig(level=logging.DEBUG)` o con el flag `--verbose` de la CLI.

**Status:** ✅ Logging añadido (P4-04). No hay otros problemas de correctitud conocidos.

---

### `downloader.py` — PyPI Client

**What it does:** Fetches package metadata from the PyPI JSON API and downloads the archive to a temp directory. Uses only `urllib` from stdlib (no `requests`).

**Distribution priority:**
1. `sdist` / `.tar.gz` — preferred (includes `setup.py`)
2. Platform-independent wheel (`any` in filename)
3. First available URL (fallback)

**Known issues:**
- `User-Agent` header is hardcoded as `pkgxray/0.1.0` (stale) — pending P5-01
- No offline/cache mode — every scan hits the network

**Status:** Functional. Minor cosmetic issue with User-Agent (pending P5-01).

---

### `extractor.py` — Archive Parser

**What it does:** Opens a downloaded `.tar.gz`, `.tgz`, `.whl`, or `.zip` archive and returns all Python-relevant files as in-memory `ExtractedFile` objects.

**Guards applied per file:**
- Skips directories
- ✅ **[Fixed P1-02]** Skips path traversal via `os.path.normpath()` — rejects `".."`, `"/absolute"`, and the normpath bypass `"foo/./../../evil.py"`
- Skips files > 5 MB
- Skips non-Python files (`.py`, `setup.cfg`, `pyproject.toml`)

**Known issues:**
- `ExtractedFile.is_setup` flag is set correctly but never consumed by any downstream code (pending P5-02).

**Status:** ✅ Path traversal fix applied (P1-02). The unused `is_setup` flag is dead code (pending P5-02).

---

### `scorer.py` — Risk Scoring Engine

**What it does:** Converts a list of `Finding` objects into a single integer risk score (0–100) and a risk level label.

**Scoring logic:**

| Severity | Weight |
|----------|--------|
| LOW      | 1      |
| MEDIUM   | 3      |
| HIGH     | 7      |
| CRITICAL | 15     |

Two-level capping:
1. **Per-analyser cap: 20 points** — prevents a single analyser from dominating the score
2. **Global cap: 100 points**

**Risk level thresholds:**

| Score   | Level    |
|---------|----------|
| 0–20    | LOW      |
| 21–40   | MODERATE |
| 41–70   | HIGH     |
| 71–100  | CRITICAL |

**✅ Recalibrated (P3-02):** Per-analyser caps are now heterogeneous (env_access=5, network=8, obfuscation=20, etc.) and combo bonuses fire for dangerous pattern combinations (env_access+network, obfuscation+code_exec, etc.). Known-clean packages now score LOW/MODERATE.

**Status:** ✅ Recalibrated (P3-02). Scores validated with integration tests (P3-03).

---

### `reporter.py` — Output Formatter

**What it does:** Converts a `ScanResult` into terminal (rich), JSON, or HTML output.

**Known issues:**
- `Console(width=200)` ignores the terminal's actual width — output wraps awkwardly on narrow terminals.

**✅ XSS fix (P1-01):** All user-controlled strings (`description`, `filename`, `code_snippet`, `analyzer_name`, `package_name`, `version`) are now HTML-escaped before embedding in the HTML report.

**Status:** ✅ XSS fixed (P1-01). Width issue is cosmetic.

---

### `cli.py` — Command-Line Interface

**What it does:** Exposes `pkgxray scan <package>` via `click`. Supports `--version`, `--format`, `--output` flags.

**✅ [P4-01]:** Nuevo flag `--fail-above N` — sale con código 1 si `risk_score >= N`, útil en pipelines CI/CD.

**✅ [P4-04]:** Nuevo flag `--verbose` — activa `logging.DEBUG` para ver warnings de analizadores y pasos del pipeline.

**Known issues:**
- `@click.version_option(version="0.1.0")` es stale — muestra `0.1.0` (pendiente P5-01).

**Status:** ✅ --fail-above (P4-01) y --verbose (P4-04) implementados. Version string fix pendiente P5-01.

---

### `utils.py` — Utilities

**What it does:** Nothing. Empty placeholder file.

**Status:** Empty. Reserved for future shared helpers.

---

## Analyzers (`src/pkgxray/analyzers/`)

All analyzers inherit `BaseAnalyzer`. They receive a file's source code as a string and return a list of `Finding` objects. All use `ast.parse()` — never execute code.

### `base.py` — Shared Primitives

Defines `Severity`, `Finding`, `ExtractedFile`, `ScanResult`, `BaseAnalyzer`, `build_parent_map()`, `is_module_level()`.

**`is_module_level(node)` — key behaviour:** Returns `True` if the node has no `FunctionDef` or `AsyncFunctionDef` ancestor. Used to escalate severity to CRITICAL (code running at import time is the highest-risk case).

**✅ [Fixed P2-04]:** `ClassDef` is no longer treated as a barrier. Code in a class body (outside any method) runs at import time and is now correctly classified as module-level, escalating severity to CRITICAL.

**`build_parent_map()` performance:** Called per-file by each analyzer that uses `is_module_level`. Not a correctness issue.

**Status:** ✅ ClassDef gap fixed (P2-04).

---

### `code_exec.py` — Dynamic Code Execution

**Detects:** `eval()`, `exec()`, `compile()` calls.

**Severities:** `eval` → HIGH, `exec` → CRITICAL, `compile` → HIGH. Escalated to CRITICAL if at module level.

**Does NOT detect:**
- `obj.exec()` (attribute call)
- Aliased: `e = eval; e(...)`
- `getattr(builtins, "exec")(...)`

**Status:** Functional. Alias bypass is a known limitation.

---

### `network.py` — Network Calls

**Detects:** `urlopen`, `create_connection` (always), `connect` (with DB receiver exclusion), HTTP methods (`get`, `post`, etc.) when receiver is in a known HTTP-client set.

**✅ [Fixed P2-02]:** New `_extract_receiver_name()` helper resolves chained attribute chains. `self.session.get(url)` is now detected because `"session"` is extracted from the chain and matched against `_KNOWN_HTTP_RECEIVERS`.

**Does NOT detect:**
- Module-aliased imports: `import requests as r; r.get(url)` — known limitation, out of scope for v0.3

**Status:** ✅ Chained attribute detection fixed (P2-02).

---

### `filesystem.py` — Filesystem Access

**Detects:**
- `rmtree` (always — unambiguous), `remove` and `unlink` only when receiver ∈ `{os, pathlib, Path}`.
- String literals matching sensitive paths.

**✅ [Fixed P2-01]:** `list.remove(x)` and `set.remove(x)` are no longer flagged. Receiver filtering prevents false positives on any object that happens to have a method named `remove` or `unlink`.

**✅ [Fixed P2-05]:** Destructive calls at module level (including class bodies) are escalated to CRITICAL.

**✅ [Fixed P2-06]:** `_SENSITIVE_PATHS` expanded to include `~/.kube/config` (CRITICAL), `~/.npmrc`, `~/.pypirc`, `~/.azure/`, `~/.gnupg/`, `~/.bash_profile`, `~/.docker/config.json`, `~/.git-credentials`, `~/.config/gcloud/` (HIGH).

**Status:** ✅ Receiver filtering (P2-01), module-level escalation (P2-05), expanded paths (P2-06).

---

### `env_access.py` — Environment Variables

**Detects:** `os.environ[key]`, `os.getenv(key)`, `os.environ.get(key)`.

**Severity:** HIGH if key name matches a sensitive keyword, MEDIUM if dynamic, LOW otherwise.

**✅ [Fixed P2-05]:** Sensitive accesses (HIGH/MEDIUM) at module level are now escalated to CRITICAL. LOW accesses (HOME, PATH, TERM…) are never escalated to avoid noise.

**✅ [Fixed P2-06]:** `_SENSITIVE_ENV_KEYWORDS` expanded with: `AWS_ACCESS_KEY`, `AZURE_`, `GCP_`, `GITHUB_TOKEN`, `STRIPE_KEY`, `SLACK_WEBHOOK`, `TWILIO_SID`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `JWT_SECRET`, `SESSION_SECRET`, `MONGO_URI`, and more.

**Status:** ✅ Module-level escalation (P2-05), expanded keywords (P2-06).

---

### `subprocess_calls.py` — OS Command Execution

**Detects:** `subprocess.run/call/Popen/check_output/check_call` (receiver must be exactly `subprocess`) and `os.system/popen/execvp/execv` (receiver must be exactly `os`).

**Does NOT detect:**
- `import subprocess as sp; sp.run(...)` — receiver check is exact name match
- `os.spawn*` family
- `pty.spawn()`, `commands.getoutput()`

**Status:** Functional. Alias bypass is a known limitation.

---

### `obfuscation.py` — Code Obfuscation

**Detects:**
- `exec(base64.b64decode(...))` / `eval(base64.b64decode(...))` → CRITICAL
- `codecs.decode(data, "rot...")` → MEDIUM
- `.fromhex(...)` calls → MEDIUM
- Strings with 10+ consecutive `\xNN` escapes and length > 100 chars → HIGH

**Note:** `base64.b64decode()` alone is NOT flagged — it is ubiquitous in legitimate code. Only the `exec(b64decode(...))` combination is flagged.

**Status:** Well-calibrated. Low false-positive risk.

---

### `setup_scripts.py` — Installation Hooks

**Detects (in `setup.py` only):**
- Classes inheriting from setuptools command base classes (`install`, `develop`, etc.) that define `run` or `__init__` → CRITICAL
- Dangerous imports in `setup.py` (`subprocess`, `socket`, `urllib`, etc.) → HIGH
- Dangerous direct calls in `setup.py` (`eval`, `exec`, `urlopen`, `os.system`, etc.) → CRITICAL

**Note:** `subprocess.run()` is NOT in the dangerous-calls list by design — it is common in legitimate setup.py for dependency checking.

**Status:** Well-targeted. Low false-positive risk.

---

### `dynamic_imports.py` — Dynamic Imports

**Detects:** `__import__(...)`, `importlib.import_module(...)`.

**Severity rules (inside a function):**
- `__import__("json")` static arg → MEDIUM (equivalent to `import json`)
- `__import__(variable)` dynamic arg → HIGH
- `importlib.import_module("json")` static → MEDIUM
- `importlib.import_module(variable)` dynamic → HIGH

**✅ [Fixed P2-03]:** `importlib.import_module()` now requires receiver to be `importlib`. `some_obj.import_module("x")` is no longer flagged.

**✅ [Fixed P2-03]:** `__import__("json")` with a static string literal is now MEDIUM (was HIGH) — functionally equivalent to `import json`.

**✅ [Fixed P2-05]:** Any dynamic import at module level (class body included) → CRITICAL.

**Status:** ✅ Receiver check (P2-03), severity calibration (P2-03), module-level escalation (P2-05).

---

## Known Issues Summary

| Priority | Location | Issue | Status |
|----------|----------|-------|--------|
| ~~HIGH~~ | ~~`filesystem.py`~~ | ~~`list.remove()` flagged as destructive filesystem call~~ | ✅ Fixed P2-01 |
| ~~HIGH~~ | ~~`scorer.py`~~ | ~~Per-analyser cap too high, legitimate packages score CRITICAL~~ | ✅ Fixed P3-02 |
| ~~HIGH~~ | ~~`network.py`~~ | ~~Chained attribute HTTP calls missed (`self.session.get(...)`)~~ | ✅ Fixed P2-02 |
| ~~MEDIUM~~ | ~~`base.py`~~ | ~~Class-body code not classified as module-level~~ | ✅ Fixed P2-04 |
| MEDIUM | `subprocess_calls.py` | Aliased module imports bypassed (`import subprocess as sp`) | Out of scope v0.3 |
| LOW | `cli.py` | `--version` shows `0.1.0` instead of current version | Pending P5-01 |
| LOW | `downloader.py` | `User-Agent` header shows `0.1.0` | Pending P5-01 |
| LOW | `extractor.py` | `ExtractedFile.is_setup` field set but never consumed | Pending P5-02 |
| LOW | `utils.py` | Empty placeholder file | Pending P5-02 |
