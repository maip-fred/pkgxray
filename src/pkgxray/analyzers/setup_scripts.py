"""Analizador de patrones peligrosos en archivos setup.py."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

_SETUP_BASE_CLASSES = {"install", "develop", "egg_info", "sdist", "build_py", "build_ext"}

_DANGEROUS_IMPORTS_IN_SETUP = {"subprocess", "socket", "urllib", "requests", "httpx"}

# Solo llamadas que son inherentemente sospechosas en setup.py.
# Se excluye "run" y "call" para evitar falsos positivos: casi todo setup.py
# legítimo llama subprocess.run() o Popen() para verificar dependencias del sistema.
# El patrón peligroso real ya se captura en la sección de hooks de instalación (ClassDef).
_DANGEROUS_CALLS_IN_SETUP = {
    "eval": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "urlopen": Severity.CRITICAL,
    "urlretrieve": Severity.CRITICAL,
    "system": Severity.CRITICAL,
    "popen": Severity.CRITICAL,
    "Popen": Severity.CRITICAL,
}


class SetupScriptAnalyzer(BaseAnalyzer):
    name = "setup_scripts"
    description = "Detecta patrones peligrosos en archivos setup.py"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza setup.py en busca de hooks peligrosos de post-instalación.

        Este analizador solo produce hallazgos para archivos setup.py.
        """
        if "setup.py" not in filename.lower():
            return []

        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []

        for node in ast.walk(tree):
            # A) Clases que sobreescriben hooks de install/develop
            if isinstance(node, ast.ClassDef):
                base_names = set()
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        base_names.add(base.id)
                    elif isinstance(base, ast.Attribute):
                        base_names.add(base.attr)

                if base_names & _SETUP_BASE_CLASSES:
                    # Verificar si la clase tiene un método 'run' o '__init__'
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name in ("run", "__init__"):
                            snippet = lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else ""
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                description=(
                                    f"La clase '{node.name}' sobreescribe un comando de instalación "
                                    f"y tiene un método '{item.name}' — vector de ataque por hook de post-instalación"
                                ),
                                filename=filename,
                                line_number=node.lineno,
                                code_snippet=snippet,
                                analyzer_name=self.name,
                            ))

            # B) Importaciones peligrosas en setup.py
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    base_mod = alias.name.split(".")[0]
                    if base_mod in _DANGEROUS_IMPORTS_IN_SETUP:
                        snippet = lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else ""
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            description=f"Módulo peligroso '{alias.name}' importado en setup.py",
                            filename=filename,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base_mod = module.split(".")[0]
                if base_mod in _DANGEROUS_IMPORTS_IN_SETUP:
                    snippet = lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        description=f"Módulo peligroso '{module}' importado en setup.py",
                        filename=filename,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

            # C) Llamadas peligrosas en setup.py
            elif isinstance(node, ast.Call):
                func = node.func
                line_num = node.lineno
                snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""

                call_name = None
                if isinstance(func, ast.Name) and func.id in _DANGEROUS_CALLS_IN_SETUP:
                    call_name = func.id
                elif isinstance(func, ast.Attribute) and func.attr in _DANGEROUS_CALLS_IN_SETUP:
                    call_name = func.attr

                if call_name:
                    findings.append(Finding(
                        severity=_DANGEROUS_CALLS_IN_SETUP[call_name],
                        description=f"Se encontró llamada peligrosa '{call_name}()' en setup.py",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

        return findings
