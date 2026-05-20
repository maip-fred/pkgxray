"""Analizador de patrones sospechosos de acceso al sistema de archivos."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
)

_SENSITIVE_PATHS = {
    # Credenciales del sistema
    "/etc/passwd": Severity.CRITICAL,
    "/etc/shadow": Severity.CRITICAL,
    # Claves SSH
    "~/.ssh/": Severity.CRITICAL,
    "/.ssh/": Severity.CRITICAL,
    # Credenciales cloud
    "~/.aws/": Severity.CRITICAL,
    "/.aws/": Severity.CRITICAL,
    "~/.kube/config": Severity.CRITICAL,
    "~/.docker/config.json": Severity.HIGH,
    "~/.config/gcloud/": Severity.HIGH,
    "~/.azure/": Severity.HIGH,
    # Tokens de gestores de paquetes
    "~/.npmrc": Severity.HIGH,
    "~/.pypirc": Severity.HIGH,
    "~/.git-credentials": Severity.HIGH,
    # Claves GPG
    "~/.gnupg/": Severity.HIGH,
    # Configs de shell (vector de persistencia)
    "~/.bashrc": Severity.HIGH,
    "~/.profile": Severity.HIGH,
    "~/.zshrc": Severity.HIGH,
    "~/.bash_profile": Severity.HIGH,
    # Temp (riesgo bajo)
    "/tmp/": Severity.MEDIUM,
}

# .remove() y .unlink() solo son sospechosos si el receptor es un objeto de filesystem.
# Esto evita marcar my_list.remove(x) o my_set.remove(x) como operaciones destructivas.
_RECEIVER_RESTRICTED_ATTRS = {"remove", "unlink"}
_UNRESTRICTED_ATTRS = {"rmtree"}  # rmtree es inequívoco — siempre sospechoso
_VALID_FS_RECEIVERS = {"os", "pathlib", "Path"}


def _get_receiver_name(func_value) -> str:
    """Extrae el nombre del receptor de una llamada a método.

    Cubre los casos más comunes:
      os.remove()         → func_value = Name('os')          → 'os'
      Path('f').unlink()  → func_value = Call(Name('Path'))  → 'Path'
      path_obj.unlink()   → func_value = Name('path_obj')    → 'path_obj'
    """
    if isinstance(func_value, ast.Name):
        return func_value.id
    if isinstance(func_value, ast.Call):
        # Path("f").unlink() — el receptor es la clase que se está instanciando
        if isinstance(func_value.func, ast.Name):
            return func_value.func.id
        if isinstance(func_value.func, ast.Attribute):
            return func_value.func.attr
    if isinstance(func_value, ast.Attribute):
        return func_value.attr
    return ""


class FilesystemAnalyzer(BaseAnalyzer):
    name = "filesystem"
    description = "Detecta accesos sospechosos al sistema de archivos"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de patrones de acceso sospechoso al filesystem.

        Detecta:
          A) Llamadas destructivas (os.remove, Path.unlink, shutil.rmtree) con
             filtrado de receptor para evitar falsos positivos en list.remove().
          B) Referencias a rutas sensibles (/etc/passwd, ~/.ssh/, ~/.aws/, etc.).

        Las llamadas destructivas al nivel del módulo se elevan a CRITICAL porque
        se ejecutan automáticamente en el momento de la importación.
        """
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        parent_map = build_parent_map(tree)

        for node in ast.walk(tree):

            # ── A) Llamadas destructivas ──────────────────────────────────────
            if isinstance(node, ast.Call):
                func = node.func
                if not isinstance(func, ast.Attribute):
                    continue

                attr = func.attr
                line_num = node.lineno
                snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""

                if attr in _UNRESTRICTED_ATTRS:
                    # rmtree es inequívoco: siempre lo flaggeamos
                    at_module = is_module_level(node, parent_map)
                    severity = Severity.CRITICAL if at_module else Severity.HIGH
                    suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada destructiva al sistema de archivos '{attr}()'{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

                elif attr in _RECEIVER_RESTRICTED_ATTRS:
                    # remove/unlink: solo si el receptor parece un objeto de filesystem
                    receiver = _get_receiver_name(func.value)
                    if receiver in _VALID_FS_RECEIVERS:
                        at_module = is_module_level(node, parent_map)
                        severity = Severity.CRITICAL if at_module else Severity.HIGH
                        suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                        findings.append(Finding(
                            severity=severity,
                            description=f"Se detectó llamada destructiva al sistema de archivos '{attr}()'{suffix}",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

            # ── B) Strings con rutas sensibles ────────────────────────────────
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                for path, severity in _SENSITIVE_PATHS.items():
                    if path in value:
                        line_num = getattr(node, 'lineno', 0)
                        snippet = (
                            lines[line_num - 1].strip()[:200]
                            if line_num and line_num <= len(lines)
                            else value[:200]
                        )
                        findings.append(Finding(
                            severity=severity,
                            description=f"Se encontró la ruta sensible '{path}' en el código",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

        return findings
