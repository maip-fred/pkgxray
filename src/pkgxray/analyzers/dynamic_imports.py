"""Analizador de patrones de importación dinámica de módulos."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity


def _is_dynamic_arg(node) -> bool:
    """Retorna True si el nodo es una expresión dinámica (no un literal de string)."""
    return not isinstance(node, ast.Constant)


class DynamicImportAnalyzer(BaseAnalyzer):
    name = "dynamic_imports"
    description = "Detecta importaciones dinámicas de módulos"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de patrones de importación dinámica."""
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""

            # __import__("modulo")
            if isinstance(func, ast.Name) and func.id == "__import__":
                severity = Severity.HIGH
                findings.append(Finding(
                    severity=severity,
                    description="Se detectó llamada a __import__() — carga dinámica de módulos",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

            # importlib.import_module(...)
            elif isinstance(func, ast.Attribute) and func.attr == "import_module":
                # Si el argumento es dinámico (no literal string) → HIGH, si no → MEDIUM
                severity = Severity.MEDIUM
                if node.args and _is_dynamic_arg(node.args[0]):
                    severity = Severity.HIGH
                findings.append(Finding(
                    severity=severity,
                    description=(
                        "Se detectó llamada a importlib.import_module() con argumento dinámico"
                        if severity == Severity.HIGH
                        else "Se detectó llamada a importlib.import_module()"
                    ),
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

        return findings
