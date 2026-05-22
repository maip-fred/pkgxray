"""Analizador de archivos de configuración: pyproject.toml y setup.cfg."""

import configparser
import io
import logging
import re
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

_logger = logging.getLogger(__name__)

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

TOMLLIB_AVAILABLE: bool = tomllib is not None

# Paquetes de build que son sospechosos en [build-system].requires.
# Paquetes legítimos comunes (setuptools, hatchling, flit, etc.) no están aquí.
_SUSPICIOUS_BUILD_DEPS = {
    "requests", "httpx", "urllib3", "paramiko", "fabric",
    "boto3", "google-cloud", "azure",
}

# Comandos de shell sospechosos en entrypoints.
_SHELL_KEYWORDS = {"curl", "wget", "bash", "sh", "nc", "ncat", "python -c", "eval"}

# Entrypoints cortos (≤ 2 chars) necesitan coincidencia de palabra completa para
# evitar falsos positivos en identificadores Python (ej. "sh" en "bash_utils").
_SHORT_SHELL_KWS = {kw for kw in _SHELL_KEYWORDS if len(kw) <= 2}

# Regex para detectar un Python entrypoint válido: "module.submodule:function".
# Los entrypoints Python nunca contienen espacios ni metacaracteres de shell.
_PYTHON_EP_RE = re.compile(r'^[\w][\w.\-]*:[\w][\w.]*(\s*\[[\w,\s]*\])?$')

# Campos de pyproject.toml donde se pueden definir scripts/entrypoints.
_SCRIPT_FIELDS = {"scripts", "gui-scripts", "entry-points", "entry_points"}

# Flag para emitir el warning de tomllib ausente solo una vez por sesión.
# Intentionally never reset: the warning fires at most once per process lifetime.
# Test isolation note: if a test triggers the warning, subsequent tests in the
# same process will not see it even if they expect it.  Reset this flag in
# test setUp/teardown when needed.
_warned_no_tomllib = False


def _reset_tomllib_warning() -> None:
    """Resets the 'tomllib unavailable' warning flag. For use in tests only."""
    global _warned_no_tomllib
    _warned_no_tomllib = False


def _find_line(content: str, *search_strings: str) -> int:
    """Returns the line number (1-based) of the first non-comment line that
    contains any of the search strings.

    Skips lines that start with '#' (TOML/INI comments) or ';' (INI comments)
    after stripping leading whitespace.  Returns 0 if no match is found.

    This is a best-effort approximation: parsers (tomllib, configparser) do not
    expose line numbers, so we search the raw text after parsing.
    """
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith(";"):
            continue
        if any(s in line for s in search_strings):
            return i
    return 0


def _is_python_ep(target: str) -> bool:
    """Retorna True si target parece un entrypoint Python válido (module:function)."""
    return bool(_PYTHON_EP_RE.match(target.strip()))


def _contains_shell_keyword(target_lower: str) -> str:
    """Retorna el primer keyword de shell encontrado en target_lower, o '' si ninguno."""
    for kw in _SHELL_KEYWORDS:
        if kw in _SHORT_SHELL_KWS:
            # Para keywords cortos (sh, nc): exigir palabra completa con \b
            if re.search(r'\b' + re.escape(kw) + r'\b', target_lower):
                return kw
        else:
            if kw in target_lower:
                return kw
    return ""


def _check_pyproject(content: str, filename: str) -> List[Finding]:
    """Analiza un archivo pyproject.toml en busca de configuraciones sospechosas."""
    global _warned_no_tomllib
    if tomllib is None:
        if not _warned_no_tomllib:
            _logger.warning(
                "tomllib no disponible y tomli no está instalado — '%s' no será analizado. "
                "Instala tomli para soporte en Python < 3.11: pip install tomli",
                filename,
            )
            _warned_no_tomllib = True
        return []

    findings = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    # --- [build-system].requires -------------------------------------------
    build_system = data.get("build-system", {})
    requires = build_system.get("requires", [])
    if isinstance(requires, list):
        for dep in requires:
            dep_name = str(dep).split("[")[0].split(">=")[0].split("==")[0].strip().lower()
            if dep_name in _SUSPICIOUS_BUILD_DEPS:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    description=(
                        f"Dependencia de build sospechosa en [build-system].requires: '{dep}' — "
                        "paquetes de red/cloud rara vez son necesarios en tiempo de build"
                    ),
                    filename=filename,
                    line_number=_find_line(content, f'"{dep}"', f"'{dep}'", dep_name),
                    code_snippet=f"requires = [..., \"{dep}\", ...]",
                    analyzer_name="config_files",
                ))

    # --- [project].scripts / entry-points ----------------------------------
    project = data.get("project", {})
    for field in _SCRIPT_FIELDS:
        scripts = project.get(field, {})
        if not isinstance(scripts, dict):
            continue
        for name, target in scripts.items():
            target_str = str(target).strip()
            if _is_python_ep(target_str):
                # Entrypoint Python legítimo (module:function) — no contiene shell commands
                continue
            matched_kw = _contains_shell_keyword(target_str.lower())
            if matched_kw:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    description=(
                        f"Entrypoint '{name}' contiene comando de shell sospechoso: '{matched_kw}'"
                    ),
                    filename=filename,
                    line_number=_find_line(content, name),
                    code_snippet=f"{name} = {target_str[:120]}",
                    analyzer_name="config_files",
                ))

    # --- [tool.hatch] / [tool.*] post-install hooks ------------------------
    tool = data.get("tool", {})
    for tool_name, tool_cfg in tool.items():
        if not isinstance(tool_cfg, dict):
            continue
        hooks = tool_cfg.get("hooks", {})
        if isinstance(hooks, dict) and hooks:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                description=(
                    f"Se detectaron hooks definidos en [tool.{tool_name}].hooks — "
                    "revisar que no ejecuten código arbitrario en tiempo de instalación"
                ),
                filename=filename,
                line_number=_find_line(content, "hooks"),
                code_snippet=str(list(hooks.keys()))[:120],
                analyzer_name="config_files",
            ))

    return findings


def _check_setup_cfg(content: str, filename: str) -> List[Finding]:
    """Analiza un archivo setup.cfg en busca de configuraciones sospechosas."""
    findings = []
    parser = configparser.ConfigParser()
    try:
        parser.read_file(io.StringIO(content))
    except Exception:
        return []

    # --- [options].install_requires ----------------------------------------
    install_requires = ""
    if parser.has_option("options", "install_requires"):
        install_requires = parser.get("options", "install_requires")
    for line in install_requires.splitlines():
        dep_name = line.strip().split("[")[0].split(">=")[0].split("==")[0].strip().lower()
        if dep_name in _SUSPICIOUS_BUILD_DEPS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                description=(
                    f"Dependencia sospechosa en [options].install_requires: '{line.strip()}'"
                ),
                filename=filename,
                line_number=_find_line(content, dep_name),
                code_snippet=line.strip()[:120],
                analyzer_name="config_files",
            ))

    # --- [options.entry_points] --------------------------------------------
    if parser.has_section("options.entry_points"):
        for _group_key, group_value in parser.items("options.entry_points"):
            for ep_line in group_value.splitlines():
                ep_line = ep_line.strip()
                if not ep_line or "=" not in ep_line:
                    continue
                ep_name, ep_target = ep_line.split("=", 1)
                ep_name = ep_name.strip()
                ep_target = ep_target.strip()
                if _is_python_ep(ep_target):
                    # Entrypoint Python legítimo — no contiene shell commands
                    continue
                matched_kw = _contains_shell_keyword(ep_target.lower())
                if matched_kw:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        description=(
                            f"Entrypoint '{ep_name}' contiene comando de shell sospechoso: '{matched_kw}'"
                        ),
                        filename=filename,
                        line_number=_find_line(content, ep_name),
                        code_snippet=f"{ep_name} = {ep_target[:120]}",
                        analyzer_name="config_files",
                    ))

    return findings


class ConfigFileAnalyzer(BaseAnalyzer):
    name = "config_files"
    description = "Analiza pyproject.toml y setup.cfg en busca de configuraciones sospechosas"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,   # accepted but not used by this analyser
    ) -> List[Finding]:
        # tree, parent_map, and aliases no se usan: los configs son TOML/INI, no AST Python
        lower = filename.lower()
        if lower.endswith("pyproject.toml"):
            return _check_pyproject(source_code, filename)
        if lower.endswith("setup.cfg"):
            return _check_setup_cfg(source_code, filename)
        return []
