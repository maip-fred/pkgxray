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

# ctypes functions that load and execute native libraries (#4)
_CTYPES_LOAD_ATTRS = {"CDLL", "WinDLL", "OleDLL", "PyDLL", "LoadLibrary"}


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

        # #5: pre-pass — collect simple variable-to-dangerous-function assignments
        # Detects: e = exec; e("payload")
        _var_aliases: dict = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                if node.value.id in _DANGEROUS_FUNCS:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            _var_aliases[target.id] = node.value.id

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            # eval / exec / compile — direct and import-aliased (#5 variable aliasing included)
            if isinstance(func, ast.Name):
                canonical = aliases.get(func.id, func.id)
                if canonical not in _DANGEROUS_FUNCS:
                    # Check variable-assignment alias: e = exec; e(...)
                    canonical = _var_aliases.get(func.id, canonical)
                if canonical not in _DANGEROUS_FUNCS:
                    continue
                func_name = canonical
                severity = Severity.CRITICAL if at_module else _SEVERITY_MAP[func_name]
                findings.append(Finding(
                    severity=severity,
                    description=f"Se detectó llamada a {func_name}() — permite ejecución arbitraria de código{suffix}",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

            # ctypes.CDLL / ctypes.WinDLL / ctypes.cdll.LoadLibrary (#4)
            elif isinstance(func, ast.Attribute):
                attr = func.attr
                receiver = func.value

                # ctypes.CDLL("lib.so") — direct attribute on ctypes module
                if attr in _CTYPES_LOAD_ATTRS and isinstance(receiver, ast.Name):
                    canonical_recv = aliases.get(receiver.id, receiver.id)
                    if canonical_recv == "ctypes":
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            description=f"Se detectó ctypes.{attr}() — carga y ejecuta código nativo (native library){suffix}",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

                # ctypes.cdll.LoadLibrary("lib.so") — chained attribute access
                elif attr == "LoadLibrary" and isinstance(receiver, ast.Attribute):
                    if receiver.attr == "cdll" and isinstance(receiver.value, ast.Name):
                        canonical_recv = aliases.get(receiver.value.id, receiver.value.id)
                        if canonical_recv == "ctypes":
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                description=f"Se detectó ctypes.cdll.LoadLibrary() — carga y ejecuta código nativo (native library){suffix}",
                                filename=filename,
                                line_number=line_num,
                                code_snippet=snippet,
                                analyzer_name=self.name,
                            ))

        return findings
