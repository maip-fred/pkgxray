"""Analizador de patrones de ejecución dinámica de código (eval, exec, compile)."""

import ast
from typing import List, Optional

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

# Names whose subscript gives access to builtin functions as a dict
_BUILTIN_DICT_NAMES = {"__builtins__", "vars", "globals", "locals"}

# Names that refer to the builtins module itself (for getattr target)
_BUILTINS_MOD_NAMES = {"__builtins__", "builtins"}


def _dangerous_func_from_indirect_call(func_node) -> Optional[str]:
    """Returns the dangerous function name if func_node is an indirect call pattern.

    Detects two patterns:
      __builtins__["exec"](...)  — ast.Subscript on a builtins container
      getattr(__builtins__, "exec")(...) — ast.Call to getattr with builtins + literal

    Returns the canonical function name ("exec", "eval", "compile") or None.
    """
    # Pattern 1: __builtins__["exec"] / vars()["exec"] / globals()["exec"]
    if isinstance(func_node, ast.Subscript):
        container = func_node.value
        slice_node = func_node.slice

        is_builtin_container = (
            isinstance(container, ast.Name) and container.id in _BUILTIN_DICT_NAMES
        ) or (
            isinstance(container, ast.Call)
            and isinstance(container.func, ast.Name)
            and container.func.id in _BUILTIN_DICT_NAMES
        )

        if (
            is_builtin_container
            and isinstance(slice_node, ast.Constant)
            and isinstance(slice_node.value, str)
            and slice_node.value in _DANGEROUS_FUNCS
        ):
            return slice_node.value

    # Pattern 2: getattr(__builtins__, "exec") / getattr(builtins, "exec")
    if (
        isinstance(func_node, ast.Call)
        and isinstance(func_node.func, ast.Name)
        and func_node.func.id == "getattr"
        and len(func_node.args) >= 2
    ):
        obj, attr_arg = func_node.args[0], func_node.args[1]
        is_builtins_obj = isinstance(obj, ast.Name) and obj.id in _BUILTINS_MOD_NAMES
        if (
            is_builtins_obj
            and isinstance(attr_arg, ast.Constant)
            and isinstance(attr_arg.value, str)
            and attr_arg.value in _DANGEROUS_FUNCS
        ):
            return attr_arg.value

    return None


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

            # __builtins__["exec"](...) / getattr(builtins, "exec")(...) (#3)
            else:
                func_name = _dangerous_func_from_indirect_call(func)
                if func_name:
                    severity = Severity.CRITICAL if at_module else _SEVERITY_MAP.get(func_name, Severity.HIGH)
                    findings.append(Finding(
                        severity=severity,
                        description=(
                            f"Se detectó llamada indirecta a {func_name}() mediante "
                            f"acceso a __builtins__ — técnica de evasión de análisis estático{suffix}"
                        ),
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

        return findings
