"""Persistent disk cache for pkgxray scan results, keyed by archive SHA-256."""

import json
import os
from pathlib import Path
from typing import Optional

from pkgxray.analyzers.base import Finding, ScanResult, Severity

_CACHE_VERSION = 1


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
    findings = [
        Finding(
            analyzer_name=f["analyzer_name"],
            severity=Severity[f["severity"]],
            description=f["description"],
            filename=f["filename"],
            line_number=f.get("line_number", 0),
            code_snippet=f.get("code_snippet", ""),
        )
        for f in data.get("findings", [])
    ]
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


def read(sha256: str) -> Optional[ScanResult]:
    """Load a cached ScanResult by archive SHA-256. Returns None on any miss or error."""
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
    """Persist a ScanResult keyed by archive SHA-256. Disk failures are silently ignored."""
    cache_dir = get_cache_dir()
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{sha256}.json"
        cache_file.write_text(
            json.dumps(_serialize(result), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
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
