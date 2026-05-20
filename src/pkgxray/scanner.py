"""Orquestador principal del escáner de pkgxray."""

import ast
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

import tarfile
import zipfile

from pkgxray import downloader, extractor, scorer
from pkgxray.extractor import _is_binary_file
from pkgxray.analyzers import get_all_analyzers
from pkgxray.analyzers.base import ScanResult, build_parent_map, collect_import_aliases
from pkgxray.analyzers.config_files import ConfigFileAnalyzer, TOMLLIB_AVAILABLE
from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer
from pkgxray.downloader import DownloadError, PackageNotFoundError


def _count_binary_files(archive_path) -> int:
    """Returns the number of binary extension files in the archive."""
    count = 0
    name = str(archive_path).lower()
    try:
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and _is_binary_file(member.name):
                        count += 1
        elif name.endswith(".whl") or name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if not info.is_dir() and _is_binary_file(info.filename):
                        count += 1
    except Exception:
        pass
    return count


def scan(package_name: str, version: Optional[str] = None) -> ScanResult:
    """Analiza un paquete de PyPI en busca de comportamiento sospechoso sin instalarlo.

    Descarga el archivo del paquete, extrae los archivos Python, ejecuta todos los
    analizadores, calcula el puntaje de riesgo y retorna un ScanResult completo.

    Args:
        package_name: Nombre del paquete de PyPI a analizar.
        version: Versión específica opcional. Si es None, analiza la última versión.

    Returns:
        ScanResult con todos los hallazgos, puntaje y metadatos.

    Raises:
        PackageNotFoundError: Si el paquete no se encuentra en PyPI.
        DownloadError: Si el paquete no puede descargarse.
    """
    # TODO (Phase 7): Add a disk-based or in-memory cache keyed on
    # (package_name, version, archive_sha256) to avoid re-downloading and
    # re-analysing the same package version on repeated calls.
    # See deficiency #15 in pkgxray_deficiency_tracking_v2.md.
    tmp_dir = tempfile.mkdtemp(prefix="pkgxray_scan_")
    try:
        # Paso 1: Descarga
        archive_path, actual_version = downloader.download_package(
            package_name, version, dest_dir=tmp_dir
        )

        # Paso 2: Extracción
        extracted_files = extractor.extract_python_files(archive_path)

        # Count binary files in the archive (not extracted, just inspected by name)
        binary_files_found = _count_binary_files(archive_path)

        # Paso 3: Análisis
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

        # Paso 4: Puntaje
        risk_score, risk_level = scorer.calculate_risk_score(all_findings)
        summary = scorer.get_summary(all_findings)

        # Paso 5: Retornar resultado
        return ScanResult(
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

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
