"""Analizador de patrones de ejecución de comandos del sistema operativo."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
    collect_import_aliases,
)

_SUBPROCESS_ATTRS = {
    "run": Severity.HIGH,
    "call": Severity.HIGH,
    "Popen": Severity.CRITICAL,
    "check_output": Severity.HIGH,
    "check_call": Severity.HIGH,
    "getoutput": Severity.HIGH,           # #2: executes shell commands
    "getstatusoutput": Severity.HIGH,     # #2: executes shell commands
}

_OS_ATTRS = {
    "system": Severity.CRITICAL,
    "popen": Severity.CRITICAL,
    "execvp": Severity.CRITICAL,
    "execv": Severity.CRITICAL,
    "spawnl": Severity.CRITICAL,          # #1: os.spawn* family
    "spawnle": Severity.CRITICAL,
    "spawnlp": Severity.CRITICAL,
    "spawnlpe": Severity.CRITICAL,
    "spawnv": Severity.CRITICAL,
    "spawnve": Severity.CRITICAL,
    "spawnvp": Severity.CRITICAL,
    "spawnvpe": Severity.CRITICAL,
}

# #3: pty.spawn() opens an interactive shell
_PTY_ATTRS = {"spawn": Severity.CRITICAL}


class SubprocessAnalyzer(BaseAnalyzer):
    name = "subprocess"
    description = "Detecta ejecución de comandos del sistema operativo"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,
    ) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas reales a subprocess y os.

        Solo se reportan llamadas concretas (subprocess.run, os.system, etc.),
        no las importaciones — importar subprocess es legítimo en muchos paquetes.
        Las llamadas al nivel del módulo (fuera de funciones/clases) se elevan a
        CRITICAL porque se ejecutan automáticamente al importar el paquete.
        """
        if tree is None:
            tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        if parent_map is None:
            parent_map = build_parent_map(tree)
        if aliases is None:
            aliases = collect_import_aliases(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)

            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                raw_receiver = func.value.id
                canonical = aliases.get(raw_receiver, raw_receiver)

                # subprocess.run/call/Popen/etc. — including aliased module names
                if canonical == "subprocess" and func.attr in _SUBPROCESS_ATTRS:
                    base_severity = _SUBPROCESS_ATTRS[func.attr]
                    severity = Severity.CRITICAL if at_module else base_severity
                    suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada a subprocess.{func.attr}() — ejecuta comandos del sistema{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

                # os.system/popen/execvp/execv/spawn* — including aliased module names
                elif canonical == "os" and func.attr in _OS_ATTRS:
                    severity = Severity.CRITICAL
                    suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada a os.{func.attr}() — ejecuta comandos del sistema{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

                # pty.spawn() — opens an interactive shell (#3)
                elif canonical == "pty" and func.attr in _PTY_ATTRS:
                    severity = Severity.CRITICAL
                    suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada a pty.{func.attr}() — abre una shell interactiva{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

            # Direct calls: from subprocess import run as subrun → subrun([...])
            elif isinstance(func, ast.Name):
                raw_name = func.id
                canonical = aliases.get(raw_name, "")
                if canonical.startswith("subprocess."):
                    attr = canonical.split(".", 1)[1]
                    if attr in _SUBPROCESS_ATTRS:
                        base_severity = _SUBPROCESS_ATTRS[attr]
                        severity = Severity.CRITICAL if at_module else base_severity
                        suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                        findings.append(Finding(
                            severity=severity,
                            description=f"Se detectó llamada a subprocess.{attr}() — ejecuta comandos del sistema{suffix}",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

        return findings
