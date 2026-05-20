"""Analizador de patrones de importación dinámica de módulos."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
)


def _is_dynamic_arg(node) -> bool:
    """Retorna True si el nodo es una expresión dinámica (no un literal constante)."""
    return not isinstance(node, ast.Constant)


class DynamicImportAnalyzer(BaseAnalyzer):
    name = "dynamic_imports"
    description = "Detecta importaciones dinámicas de módulos"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,   # accepted but not used by this analyser
    ) -> List[Finding]:
        """Analiza el código fuente en busca de patrones de importación dinámica.

        Reglas de severidad:
          - Al nivel de módulo (se ejecuta en importación) → CRITICAL siempre.
          - Dentro de una función con argumento dinámico   → HIGH.
          - Dentro de una función con argumento estático   → MEDIUM
            (__import__("json") es equivalente a import json).

        Para importlib.import_module() verifica que el receptor sea 'importlib'
        para evitar falsos positivos en objetos que tengan un método homónimo.
        """
        if tree is None:
            tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        if parent_map is None:
            parent_map = build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            module_suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            # ── __import__("modulo") ──────────────────────────────────────────
            if isinstance(func, ast.Name) and func.id == "__import__":
                if at_module:
                    severity = Severity.CRITICAL
                elif node.args and not _is_dynamic_arg(node.args[0]):
                    # __import__("json") estático — equivalente a import json
                    severity = Severity.MEDIUM
                else:
                    # __import__(variable) dinámico — peligroso
                    severity = Severity.HIGH
                findings.append(Finding(
                    severity=severity,
                    description=f"Se detectó llamada a __import__() — carga dinámica de módulos{module_suffix}",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

            # ── importlib.import_module(...) ──────────────────────────────────
            elif isinstance(func, ast.Attribute) and func.attr == "import_module":
                # Solo flaggear cuando el receptor es 'importlib'.
                # Esto evita falsos positivos en obj.import_module("x").
                if not (isinstance(func.value, ast.Name) and func.value.id == "importlib"):
                    continue
                if at_module:
                    severity = Severity.CRITICAL
                    desc = f"Se detectó llamada a importlib.import_module(){module_suffix}"
                elif node.args and _is_dynamic_arg(node.args[0]):
                    severity = Severity.HIGH
                    desc = "Se detectó llamada a importlib.import_module() con argumento dinámico"
                else:
                    severity = Severity.MEDIUM
                    desc = "Se detectó llamada a importlib.import_module()"
                findings.append(Finding(
                    severity=severity,
                    description=desc,
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

        return findings
