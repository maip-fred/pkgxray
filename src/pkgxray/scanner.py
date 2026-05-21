"""Orquestador principal del escáner de pkgxray."""

import ast
import copy
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

from pkgxray import _disk_cache, downloader, extractor, scorer
from pkgxray.analyzers import get_all_analyzers
from pkgxray.analyzers.base import ScanResult, build_parent_map, collect_import_aliases
from pkgxray.analyzers.config_files import ConfigFileAnalyzer, TOMLLIB_AVAILABLE
from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer
from pkgxray.downloader import DownloadError, PackageNotFoundError


# In-session cache: keyed on (package_name_lower, version_str) for pinned versions.
# Only populated when an explicit version is requested.  "latest" scans are never
# cached because the package contents may change between calls.
_SCAN_CACHE: dict = {}


def clear_cache() -> None:
    """Clears the in-session scan cache.

    Call this in tests or when you need fresh results for a version you have
    already scanned in the same Python session.
    """
    _SCAN_CACHE.clear()


def scan(
    package_name: str,
    version: Optional[str] = None,
    *,
    registry_url: Optional[str] = None,
) -> ScanResult:
    """Analiza un paquete de PyPI en busca de comportamiento sospechoso sin instalarlo.

    Descarga el archivo del paquete, extrae los archivos Python, ejecuta todos los
    analizadores, calcula el puntaje de riesgo y retorna un ScanResult completo.

    Args:
        package_name: Nombre del paquete de PyPI a analizar.
        version: Versión específica opcional. Si es None, analiza la última versión.
        registry_url: URL base del registro PyPI privado. None usa PKGXRAY_INDEX_URL o PyPI.

    Returns:
        ScanResult con todos los hallazgos, puntaje y metadatos.

    Raises:
        PackageNotFoundError: Si el paquete no se encuentra en el registro.
        DownloadError: Si el paquete no puede descargarse.
    """
    # Paso 1: Session cache lookup (only for pinned versions).
    if version is not None:
        cache_key = (package_name.lower(), version)
        if cache_key in _SCAN_CACHE:
            logger.debug("Session cache hit for %s==%s", package_name, version)
            return _SCAN_CACHE[cache_key]

    # Paso 2: Fetch package metadata and select distribution.
    info = downloader.get_package_info(package_name, version, registry_url=registry_url)
    actual_version = info["info"]["version"]
    url, filename, sha256 = downloader.find_best_distribution(info)

    # Paso 3: Disk cache lookup (only when PyPI provided a SHA-256 for the archive).
    if sha256:
        disk_result = _disk_cache.read(sha256)
        if disk_result is not None:
            logger.debug(
                "Disk cache hit for %s==%s (sha256=%.8s...)",
                package_name, actual_version, sha256,
            )
            if version is not None:
                cached = copy.deepcopy(disk_result)
                _SCAN_CACHE[(package_name.lower(), actual_version)] = cached
                if version != actual_version:
                    _SCAN_CACHE[(package_name.lower(), version)] = cached
            return disk_result

    tmp_dir = tempfile.mkdtemp(prefix="pkgxray_scan_")
    try:
        # Paso 4: Descarga
        archive_path = downloader.download_file(url, sha256, filename, tmp_dir)

        # Paso 5: Extracción — returns (files, binary_count) in one archive pass
        extracted_files, binary_files_found = extractor.extract_python_files(archive_path)

        # Paso 6: Análisis
        analyzers = get_all_analyzers()
        all_findings = []
        skipped_files = []

        for extracted_file in extracted_files:
            lower_fn = extracted_file.filename.lower()
            tree = None
            parent_map = None
            aliases = None

            if lower_fn.endswith(".py"):
                # Parsear una sola vez: verifica sintaxis Y produce el tree/parent_map
                # que se reutilizarán en todos los analizadores (evita N parseos duplicados).
                try:
                    tree = ast.parse(extracted_file.content)
                except SyntaxError:
                    skipped_files.append({
                        "filename": extracted_file.filename,
                        "reason": "syntax_error",
                    })
                    continue
                except Exception:
                    skipped_files.append({
                        "filename": extracted_file.filename,
                        "reason": "parse_error",
                    })
                    continue
                parent_map = build_parent_map(tree)
                aliases = collect_import_aliases(tree)
            elif extracted_file.is_config and lower_fn.endswith("pyproject.toml") and not TOMLLIB_AVAILABLE:
                # Si tomllib no está disponible, el ConfigFileAnalyzer no puede analizar
                # archivos TOML — lo registramos en skipped_files para que el usuario lo sepa.
                skipped_files.append({
                    "filename": extracted_file.filename,
                    "reason": "tomllib_unavailable",
                })
                continue

            for analyzer in analyzers:
                if extracted_file.is_config:
                    # Archivos de config (TOML/INI) no son Python — solo van a ConfigFileAnalyzer
                    if not isinstance(analyzer, ConfigFileAnalyzer):
                        continue
                elif isinstance(analyzer, SetupScriptAnalyzer):
                    # SetupScriptAnalyzer solo corre en setup.py
                    if not extracted_file.is_setup:
                        continue
                try:
                    findings = analyzer.analyze(
                        extracted_file.content,
                        extracted_file.filename,
                        tree=tree,
                        parent_map=parent_map,
                        aliases=aliases,
                    )
                    all_findings.extend(findings)
                except Exception as e:
                    # Un fallo individual en un analizador no debe abortar el escaneo completo
                    logger.warning(
                        "Analyzer '%s' falló en '%s': %s",
                        analyzer.name, extracted_file.filename, e,
                    )
                    continue

        # Paso 7: Puntaje
        risk_score, risk_level = scorer.calculate_risk_score(all_findings)
        summary = scorer.get_summary(all_findings)

        # Paso 8: Construir resultado
        result = ScanResult(
            package_name=package_name,
            version=actual_version,
            scan_date=datetime.now(timezone.utc).isoformat(),
            findings=all_findings,
            risk_score=risk_score,
            risk_level=risk_level,
            files_analyzed=len(extracted_files),
            summary=summary,
            skipped_files=skipped_files,
            binary_files_found=binary_files_found,
        )

        # Paso 9: Persist to disk cache (keyed by archive sha256, survives across sessions).
        if sha256:
            _disk_cache.write(sha256, result)

        # Paso 10: Cache pinned-version results for reuse within this session.
        # Store a deep copy so callers that mutate the returned object (#14)
        # don't corrupt future cache hits.
        if version is not None:
            cached = copy.deepcopy(result)
            _SCAN_CACHE[(package_name.lower(), actual_version)] = cached
            # Also store under the user-supplied key in case it differs from the
            # resolved version (e.g. "2" → "2.32.3"), so repeated calls with the
            # same input string hit the cache correctly.
            if version != actual_version:
                _SCAN_CACHE[(package_name.lower(), version)] = cached

        return result

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
