"""Persistent disk cache for pkgxray scan results, keyed by archive SHA-256."""

import logging
import re
import json
import os
from pathlib import Path
from typing import Optional

from pkgxray.analyzers.base import Finding, ScanResult, Severity

_logger = logging.getLogger(__name__)

_CACHE_VERSION = 1

# Disk cache eviction settings.
# When the number of cached entries exceeds MAX_CACHE_ENTRIES, the oldest
# EVICT_COUNT entries (by file modification time) are deleted before writing
# the new entry.  This keeps disk usage bounded without requiring a separate
# daemon or explicit TTL management.
MAX_CACHE_ENTRIES: int = 200
EVICT_COUNT: int = 40   # evict ~20% when the limit is hit

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

def _is_valid_sha256(value: str) -> bool:
    """Returns True if value is a well-formed lowercase hex SHA-256 digest."""
    return bool(_SHA256_RE.match(value))

def get_cache_dir() -> Path:
    """Return the platform-appropriate cache directory for pkgxray."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "pkgxray" / "cache"
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    if xdg:
        return Path(xdg) / "pkgxray"
    return Path.home() / ".cache" / "pkgxray"


def _serialize(result: ScanResult) -> dict:
    return {
        "version": _CACHE_VERSION,
        "package_name": result.package_name,
        "version_str": result.version,
        "scan_date": result.scan_date,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "files_analyzed": result.files_analyzed,
        "binary_files_found": result.binary_files_found,
        "summary": result.summary,
        "skipped_files": result.skipped_files,
        "findings": [
            {
                "analyzer_name": f.analyzer_name,
                "severity": f.severity.name,
                "description": f.description,
                "filename": f.filename,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
            }
            for f in result.findings
        ],
    }


def _deserialize(data: dict) -> ScanResult:
    findings = []
    for f in data.get("findings", []):
        try:
            severity = Severity[f["severity"].upper()]
        except (KeyError, AttributeError):
            _logger.warning(
                "Entrada de caché con severidad desconocida '%s' — omitida",
                f.get("severity"),
            )
            continue
        findings.append(Finding(
            analyzer_name=f["analyzer_name"],
            severity=severity,
            description=f["description"],
            filename=f["filename"],
            line_number=f.get("line_number", 0),
            code_snippet=f.get("code_snippet", ""),
        ))
    return ScanResult(
        package_name=data["package_name"],
        version=data["version_str"],
        scan_date=data["scan_date"],
        findings=findings,
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        files_analyzed=data["files_analyzed"],
        summary=data.get("summary", {}),
        skipped_files=data.get("skipped_files", []),
        binary_files_found=data.get("binary_files_found", 0),
    )


def _evict_if_needed(cache_dir: Path) -> int:
    """Delete the oldest EVICT_COUNT cache files if the total exceeds MAX_CACHE_ENTRIES.

    Uses file modification time (st_mtime) as a proxy for last-access time since
    Python's Path.stat() always exposes mtime portably.  Eviction failures for
    individual files are silently ignored.

    Returns:
        Number of files actually deleted.
    """
    try:
        files = list(cache_dir.glob("*.json"))
    except Exception:
        return 0

    if len(files) < MAX_CACHE_ENTRIES:
        return 0

    try:
        files.sort(key=lambda f: f.stat().st_mtime)
    except Exception:
        return 0

    evicted = 0
    for f in files[:EVICT_COUNT]:
        try:
            f.unlink()
            evicted += 1
        except Exception:
            pass

    return evicted


def read(sha256: str) -> Optional[ScanResult]:
    """Load a cached ScanResult by archive SHA-256. Returns None on any miss or error."""
    if not _is_valid_sha256(sha256):
        return None                             # reject malformed keys silently
    cache_file = get_cache_dir() / f"{sha256}.json"
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if data.get("version") != _CACHE_VERSION:
            return None
        return _deserialize(data)
    except Exception:
        return None


def write(sha256: str, result: ScanResult) -> None:
    """Persist a ScanResult keyed by archive SHA-256. Disk failures are silently ignored.

    If the number of cached entries exceeds MAX_CACHE_ENTRIES, the oldest EVICT_COUNT
    entries are deleted before the new entry is written (LRU-by-mtime eviction).
    """
    if not _is_valid_sha256(sha256):
        return                                  # reject malformed keys silently
    cache_dir = get_cache_dir()
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _evict_if_needed(cache_dir)             # evict before writing, not after
        cache_file = cache_dir / f"{sha256}.json"
        cache_file.write_text(
            json.dumps(_serialize(result), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        cache_file.chmod(0o600)                # ADD — owner read/write only
    except Exception:
        pass


def clear() -> int:
    """Delete all cached result files. Returns the number of files removed."""
    cache_dir = get_cache_dir()
    if not cache_dir.exists():
        return 0
    count = 0
    for f in cache_dir.glob("*.json"):
        try:
            f.unlink()
            count += 1
        except Exception:
            pass
    return count
