"""Analizador de patrones de ejecución de código mediante process/thread spawning."""

import ast
from typing import List, Optional

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
    collect_import_aliases,
)

# Constructor names that accept a callable via target=
_SHELL_RUNNER_CLASSES = {"Process", "Thread"}

# Executor methods where the first positional arg is the callable
_EXECUTOR_SUBMIT_ATTRS = {"submit", "map"}

# Dangerous OS functions that should not be passed as targets
_DANGEROUS_OS_ATTRS = {
    "system", "popen", "execvp", "execv",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "startfile",
}

# Dangerous subprocess functions
_DANGEROUS_SUBPROCESS_ATTRS = {
    "run", "call", "Popen", "check_output", "check_call",
    "getoutput", "getstatusoutput",
}


def _resolve_dangerous_target(target_node, aliases: dict) -> Optional[str]:
    """Return a description string if target_node is a dangerous callable, else None.

    Handles:
      os.system          → Attribute(Name('os'), 'system')
      aliased_os.system  → resolved via aliases dict
      subprocess.run     → Attribute(Name('subprocess'), 'run')
      from subprocess import run → Name('run') in aliases
    """
    if isinstance(target_node, ast.Attribute):
        attr = target_node.attr
        if isinstance(target_node.value, ast.Name):
            canonical = aliases.get(target_node.value.id, target_node.value.id)
            if canonical == "os" and attr in _DANGEROUS_OS_ATTRS:
                return f"os.{attr}"
            if canonical == "subprocess" and attr in _DANGEROUS_SUBPROCESS_ATTRS:
                return f"subprocess.{attr}"

    elif isinstance(target_node, ast.Name):
        canonical = aliases.get(target_node.id, "")
        if "." in canonical:
            mod, func = canonical.rsplit(".", 1)
            if mod == "os" and func in _DANGEROUS_OS_ATTRS:
                return canonical
            if mod == "subprocess" and func in _DANGEROUS_SUBPROCESS_ATTRS:
                return canonical

    return None


class ProcessSpawnAnalyzer(BaseAnalyzer):
    name = "process_spawn"
    description = (
        "Detecta Process/Thread/Executor con funciones peligrosas de OS como target"
    )

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,
    ) -> List[Finding]:
        """Detecta llamadas a multiprocessing.Process, threading.Thread, o
        concurrent.futures executors donde el callable objetivo (target=) es una
        función peligrosa del sistema operativo o del módulo subprocess.

        Este patrón permite evadir los analizadores de subprocess y code_exec porque
        la llamada peligrosa real no aparece directamente en el código — solo se pasa
        como referencia a un lanzador de procesos/hilos.
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
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            # Determine the call name (Process, Thread, submit, map)
            call_name = ""
            if isinstance(func, ast.Name):
                call_name = func.id
            elif isinstance(func, ast.Attribute):
                call_name = func.attr

            dangerous_target: Optional[str] = None

            if call_name in _SHELL_RUNNER_CLASSES:
                # Process(target=os.system, ...) / Thread(target=os.system, ...)
                for kw in node.keywords:
                    if kw.arg == "target":
                        dangerous_target = _resolve_dangerous_target(kw.value, aliases)
                        break

            elif call_name in _EXECUTOR_SUBMIT_ATTRS:
                # executor.submit(os.system, "cmd") — first positional arg is the callable
                if node.args:
                    dangerous_target = _resolve_dangerous_target(node.args[0], aliases)

            if dangerous_target:
                severity = Severity.CRITICAL if at_module else Severity.HIGH
                findings.append(Finding(
                    severity=severity,
                    description=(
                        f"Se detectó '{call_name}' con función peligrosa como objetivo: "
                        f"'{dangerous_target}' — ejecuta comandos del sistema en proceso/hilo separado{suffix}"
                    ),
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

        return findings
