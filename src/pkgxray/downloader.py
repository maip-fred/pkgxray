"""Descarga paquetes de PyPI sin instalarlos."""

import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Optional, Tuple

try:
    _PKGXRAY_VERSION = _pkg_version("pkgxray")
except Exception:
    _PKGXRAY_VERSION = "0.3.0"


class PackageNotFoundError(Exception):
    """Se lanza cuando un paquete no se encuentra en PyPI."""


class DownloadError(Exception):
    """Se lanza cuando un paquete no puede descargarse."""


_DEFAULT_REGISTRY = "https://pypi.org"


def _resolve_registry(registry_url: Optional[str]) -> str:
    """Return the registry base URL: explicit arg > env var > default PyPI."""
    if registry_url:
        return registry_url.rstrip("/")
    env = os.environ.get("PKGXRAY_INDEX_URL", "")
    return env.rstrip("/") if env else _DEFAULT_REGISTRY


def get_package_info(
    package_name: str,
    version: Optional[str] = None,
    *,
    registry_url: Optional[str] = None,
) -> dict:
    """Obtiene los metadatos de un paquete desde la API JSON del registro.

    Args:
        package_name: Nombre del paquete en PyPI.
        version: Versión específica opcional a consultar.
        registry_url: URL base del registro PyPI. None usa PKGXRAY_INDEX_URL o PyPI.

    Returns:
        Respuesta JSON del registro ya parseada.

    Raises:
        PackageNotFoundError: Si el paquete (o la versión) no existe.
        DownloadError: Por errores de red o de parseo.
    """
    registry = _resolve_registry(registry_url)
    if version:
        url = f"{registry}/pypi/{package_name}/{version}/json"
    else:
        url = f"{registry}/pypi/{package_name}/json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"pkgxray/{_PKGXRAY_VERSION}"})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise PackageNotFoundError(
                f"El paquete '{package_name}' no fue encontrado en el registro"
            ) from e
        raise DownloadError(f"Error HTTP {e.code} al obtener '{package_name}'") from e
    except urllib.error.URLError as e:
        raise DownloadError(f"Error de red al obtener '{package_name}': {e}") from e
    except json.JSONDecodeError as e:
        raise DownloadError(f"Error al parsear la respuesta del registro para '{package_name}': {e}") from e


def find_best_distribution(package_info: dict) -> Tuple[str, str, Optional[str]]:
    """Selecciona el mejor archivo de distribución para descargar según los metadatos.

    Orden de preferencia: sdist (.tar.gz) > wheel multiplataforma > cualquier distribución.

    Args:
        package_info: Respuesta JSON del registro para el paquete.

    Returns:
        Tupla (url_de_descarga, nombre_de_archivo, sha256_esperado_o_None).

    Raises:
        DownloadError: Si no se encuentra ninguna distribución adecuada.
    """
    urls = package_info.get("urls", [])

    def _pick(entry: dict) -> Tuple[str, str, Optional[str]]:
        sha256 = entry.get("digests", {}).get("sha256")
        return entry["url"], entry["filename"], sha256

    # Prioridad 1: sdist (.tar.gz) — contiene setup.py
    for entry in urls:
        if entry.get("packagetype") == "sdist" or entry.get("filename", "").endswith(".tar.gz"):
            return _pick(entry)

    # Prioridad 2: wheel multiplataforma (any)
    for entry in urls:
        filename = entry.get("filename", "")
        if filename.endswith(".whl") and "any" in filename:
            return _pick(entry)

    # Prioridad 3: cualquier distribución disponible
    if urls:
        return _pick(urls[0])

    raise DownloadError("No se encontró ninguna distribución adecuada para este paquete")


def download_file(
    url: str,
    expected_sha256: Optional[str],
    filename: str,
    dest_dir: str,
) -> Path:
    """Descarga un archivo desde *url* a *dest_dir/filename* y verifica el SHA-256.

    Args:
        url: URL de descarga del archivo.
        expected_sha256: Digest SHA-256 esperado, o None para omitir la verificación.
        filename: Nombre del archivo de destino.
        dest_dir: Directorio donde guardar el archivo.

    Returns:
        Path al archivo descargado.

    Raises:
        DownloadError: Por errores de red o discrepancia de checksum.
    """
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)
    output_file = dest_path / filename

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"pkgxray/{_PKGXRAY_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
        output_file.write_bytes(data)

        if expected_sha256:
            actual_sha256 = hashlib.sha256(data).hexdigest()
            if actual_sha256 != expected_sha256:
                output_file.unlink(missing_ok=True)
                raise DownloadError(
                    f"SHA-256 mismatch para '{filename}': "
                    f"esperado {expected_sha256}, obtenido {actual_sha256}"
                )
        return output_file
    except DownloadError:
        raise
    except Exception as e:
        raise DownloadError(f"Error al descargar '{filename}': {e}") from e


def download_package(
    package_name: str,
    version: Optional[str] = None,
    dest_dir: Optional[str] = None,
    *,
    registry_url: Optional[str] = None,
) -> Tuple[Path, str]:
    """Descarga el archivo de un paquete del registro sin instalarlo.

    Args:
        package_name: Nombre del paquete en PyPI.
        version: Versión específica opcional.
        dest_dir: Directorio donde guardar el archivo. Si es None, se crea un directorio temporal.
        registry_url: URL base del registro PyPI. None usa PKGXRAY_INDEX_URL o PyPI.

    Returns:
        Tupla (Path al archivo descargado, cadena con la versión real).

    Raises:
        PackageNotFoundError: Si el paquete no existe en el registro.
        DownloadError: Por errores durante la descarga.
    """
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="pkgxray_")

    try:
        package_info = get_package_info(package_name, version, registry_url=registry_url)
        actual_version = package_info["info"]["version"]
        download_url, filename, expected_sha256 = find_best_distribution(package_info)
        output_file = download_file(download_url, expected_sha256, filename, dest_dir)
        return output_file, actual_version
    except (PackageNotFoundError, DownloadError):
        raise
    except Exception as e:
        raise DownloadError(f"Error inesperado al descargar '{package_name}': {e}") from e
