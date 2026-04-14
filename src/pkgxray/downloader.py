"""Descarga paquetes de PyPI sin instalarlos."""

import json
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Tuple


class PackageNotFoundError(Exception):
    """Se lanza cuando un paquete no se encuentra en PyPI."""


class DownloadError(Exception):
    """Se lanza cuando un paquete no puede descargarse."""


PYPI_API_URL = "https://pypi.org/pypi/{package_name}/json"
PYPI_API_VERSION_URL = "https://pypi.org/pypi/{package_name}/{version}/json"


def get_package_info(package_name: str, version: Optional[str] = None) -> dict:
    """Obtiene los metadatos de un paquete desde la API JSON de PyPI.

    Args:
        package_name: Nombre del paquete en PyPI.
        version: Versión específica opcional a consultar.

    Returns:
        Respuesta JSON de PyPI ya parseada.

    Raises:
        PackageNotFoundError: Si el paquete (o la versión) no existe.
        DownloadError: Por errores de red o de parseo.
    """
    if version:
        url = PYPI_API_VERSION_URL.format(package_name=package_name, version=version)
    else:
        url = PYPI_API_URL.format(package_name=package_name)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pkgxray/0.1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise PackageNotFoundError(
                f"El paquete '{package_name}' no fue encontrado en PyPI"
            ) from e
        raise DownloadError(f"Error HTTP {e.code} al obtener '{package_name}'") from e
    except urllib.error.URLError as e:
        raise DownloadError(f"Error de red al obtener '{package_name}': {e}") from e
    except json.JSONDecodeError as e:
        raise DownloadError(f"Error al parsear la respuesta de PyPI para '{package_name}': {e}") from e


def find_best_distribution(package_info: dict) -> Tuple[str, str]:
    """Selecciona el mejor archivo de distribución para descargar según los metadatos.

    Orden de preferencia: sdist (.tar.gz) > wheel multiplataforma > cualquier distribución.

    Args:
        package_info: Respuesta JSON de PyPI para el paquete.

    Returns:
        Tupla (url_de_descarga, nombre_de_archivo).

    Raises:
        DownloadError: Si no se encuentra ninguna distribución adecuada.
    """
    urls = package_info.get("urls", [])

    # Prioridad 1: sdist (.tar.gz) — contiene setup.py
    for entry in urls:
        if entry.get("packagetype") == "sdist" or entry.get("filename", "").endswith(".tar.gz"):
            return entry["url"], entry["filename"]

    # Prioridad 2: wheel multiplataforma (any)
    for entry in urls:
        filename = entry.get("filename", "")
        if filename.endswith(".whl") and "any" in filename:
            return entry["url"], entry["filename"]

    # Prioridad 3: cualquier distribución disponible
    if urls:
        entry = urls[0]
        return entry["url"], entry["filename"]

    raise DownloadError("No se encontró ninguna distribución adecuada para este paquete")


def download_package(
    package_name: str,
    version: Optional[str] = None,
    dest_dir: Optional[str] = None,
) -> Tuple[Path, str]:
    """Descarga el archivo de un paquete de PyPI sin instalarlo.

    Args:
        package_name: Nombre del paquete en PyPI.
        version: Versión específica opcional.
        dest_dir: Directorio donde guardar el archivo. Si es None, se crea un directorio temporal.

    Returns:
        Tupla (Path al archivo descargado, cadena con la versión real).

    Raises:
        PackageNotFoundError: Si el paquete no existe en PyPI.
        DownloadError: Por errores durante la descarga.
    """
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="pkgxray_")

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    try:
        package_info = get_package_info(package_name, version)
        actual_version = package_info["info"]["version"]
        download_url, filename = find_best_distribution(package_info)

        output_file = dest_path / filename
        urllib.request.urlretrieve(download_url, str(output_file))
        return output_file, actual_version
    except (PackageNotFoundError, DownloadError):
        raise
    except Exception as e:
        raise DownloadError(f"Error inesperado al descargar '{package_name}': {e}") from e
