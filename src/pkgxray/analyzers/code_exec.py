"""Analizador de patrones de ejecución dinámica de código (eval, exec, compile)."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
    collect_import_aliases,
)

_SEVERITY_MAP = {
    "eval": Severity.HIGH,
    "exec": Severity.CRITICAL,
    "compile": Severity.HIGH,
}

_DANGEROUS_FUNCS = set(_SEVERITY_MAP.keys())


class CodeExecAnalyzer(BaseAnalyzer):
    name = "code_exec"
    description = "Detecta ejecución dinámica de código (eval, exec, compile)"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,
    ) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas a funciones de ejecución dinámica.

        eval/exec/compile a nivel del módulo se elevan a CRITICAL porque se ejecutan
        automáticamente al importar el paquete, sin necesidad de invocación explícita.
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
            if not isinstance(func, ast.Name):
                continue
            # Check if a known dangerous function has been imported under an alias
            canonical = aliases.get(func.id, func.id)
            if canonical not in _DANGEROUS_FUNCS:
                continue
            func_name = canonical

            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            severity = Severity.CRITICAL if at_module else _SEVERITY_MAP[func_name]
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            findings.append(
                Finding(
                    severity=severity,
                    description=f"Se detectó llamada a {func_name}() — permite ejecución arbitraria de código{suffix}",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                )
            )

        return findings
