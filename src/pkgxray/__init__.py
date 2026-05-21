"""pkgxray - Analiza paquetes de PyPI en busca de comportamiento sospechoso antes de instalarlos."""

from pkgxray.scanner import scan, clear_cache
from pkgxray.analyzers.base import ScanResult, Finding, Severity
from pkgxray._disk_cache import clear as clear_disk_cache

__version__ = "0.3.0"
__all__ = [
    "scan",
    "clear_cache",
    "clear_disk_cache",
    "ScanResult",
    "Finding",
    "Severity",
    "__version__",
]
