"""Utilidades compartidas de pkgxray."""

from importlib.metadata import version as _pkg_version


def get_version() -> str:
    """Retorna la versión instalada del paquete, con fallback al valor hardcoded."""
    try:
        return _pkg_version("pkgxray")
    except Exception:
        return "0.3.0"
