"""Analizador de patrones de ejecución dinámica de código (eval, exec, compile)."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level

_SEVERITY_MAP = {
    "eval": Severity.HIGH,
    "exec": Severity.CRITICAL,
    "compile": Severity.HIGH,
}

_DANGEROUS_FUNCS = set(_SEVERITY_MAP.keys())


class CodeExecAnalyzer(BaseAnalyzer):
    name = "code_exec"
    description = "Detecta ejecución dinámica de código (eval, exec, compile)"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas a funciones de ejecución dinámica.

        eval/exec/compile a nivel del módulo se elevan a CRITICAL porque se ejecutan
        automáticamente al importar el paquete, sin necesidad de invocación explícita.
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
            if not isinstance(func, ast.Name):
                continue
            if func.id not in _DANGEROUS_FUNCS:
                continue

            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            severity = Severity.CRITICAL if at_module else _SEVERITY_MAP[func.id]
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            findings.append(
                Finding(
                    severity=severity,
                    description=f"Se detectó llamada a {func.id}() — permite ejecución arbitraria de código{suffix}",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                )
            )

        return findings
