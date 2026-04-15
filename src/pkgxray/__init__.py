"""pkgxray - Analiza paquetes de PyPI en busca de comportamiento sospechoso antes de instalarlos."""

from pkgxray.scanner import scan
from pkgxray.analyzers.base import ScanResult, Finding, Severity

__version__ = "0.2.2"
__all__ = ["scan", "ScanResult", "Finding", "Severity", "__version__"]
