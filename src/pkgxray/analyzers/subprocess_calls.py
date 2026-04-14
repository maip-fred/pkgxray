"""Analizador de patrones de ejecución de comandos del sistema operativo."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level

_SUBPROCESS_ATTRS = {
    "run": Severity.HIGH,
    "call": Severity.HIGH,
    "Popen": Severity.CRITICAL,
    "check_output": Severity.HIGH,
    "check_call": Severity.HIGH,
}

_OS_ATTRS = {
    "system": Severity.CRITICAL,
    "popen": Severity.CRITICAL,
    "execvp": Severity.CRITICAL,
    "execv": Severity.CRITICAL,
}


class SubprocessAnalyzer(BaseAnalyzer):
    name = "subprocess"
    description = "Detecta ejecución de comandos del sistema operativo"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas reales a subprocess y os.

        Solo se reportan llamadas concretas (subprocess.run, os.system, etc.),
        no las importaciones — importar subprocess es legítimo en muchos paquetes.
        Las llamadas al nivel del módulo (fuera de funciones/clases) se elevan a
        CRITICAL porque se ejecutan automáticamente al importar el paquete.
        """
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        parent_map = build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)

            # subprocess.run/call/Popen/etc.
            if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                if func.attr in _SUBPROCESS_ATTRS:
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

            # os.system/popen/execvp/execv
            elif isinstance(func.value, ast.Name) and func.value.id == "os":
                if func.attr in _OS_ATTRS:
                    severity = Severity.CRITICAL  # ya son CRITICAL, nivel de módulo agrega nota
                    suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada a os.{func.attr}() — ejecuta comandos del sistema{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

        return findings
