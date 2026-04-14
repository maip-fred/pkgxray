"""Analizador de patrones de acceso a variables de entorno."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

_SENSITIVE_ENV_KEYWORDS = {
    "AWS_SECRET", "API_KEY", "TOKEN", "PASSWORD", "SECRET",
    "DATABASE_URL", "PRIVATE_KEY",
}


def _classify_env_key(key: str) -> Severity:
    """Retorna HIGH si la clave contiene un keyword sensible, LOW si no."""
    if any(kw in key.upper() for kw in _SENSITIVE_ENV_KEYWORDS):
        return Severity.HIGH
    return Severity.LOW


class EnvAccessAnalyzer(BaseAnalyzer):
    name = "env_access"
    description = "Detecta accesos a variables de entorno"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de accesos a variables de entorno.

        - Variable sensible conocida (AWS_SECRET, API_KEY, TOKEN…) → HIGH
        - Cualquier otra variable de entorno → LOW
          (acceso a TERM, PAGER, HOME, etc. es legítimo en la mayoría de los casos)
        """
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) and not isinstance(node, ast.Attribute) and not isinstance(node, ast.Subscript):
                continue

            line_num = getattr(node, 'lineno', 0)
            snippet = lines[line_num - 1].strip()[:200] if line_num and line_num <= len(lines) else ""

            # Acceso por índice: os.environ[...]
            if isinstance(node, ast.Subscript):
                value = node.value
                if isinstance(value, ast.Attribute) and value.attr == "environ":
                    if isinstance(value.value, ast.Name) and value.value.id == "os":
                        key_node = node.slice
                        # En Python 3.9+ el slice es el nodo directamente; en 3.8 es un Index
                        if hasattr(key_node, 'value') and not isinstance(key_node, ast.Constant):
                            key_node = key_node.value
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                            severity = _classify_env_key(key_node.value)
                        else:
                            # Acceso dinámico: no conocemos la clave
                            severity = Severity.MEDIUM
                        findings.append(Finding(
                            severity=severity,
                            description="Se detectó acceso a os.environ",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

            # Llamadas a os.environ.get() u os.getenv()
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    # os.getenv(...)
                    if func.attr == "getenv":
                        if node.args and isinstance(node.args[0], ast.Constant):
                            severity = _classify_env_key(str(node.args[0].value))
                        else:
                            severity = Severity.MEDIUM
                        findings.append(Finding(
                            severity=severity,
                            description="Se detectó llamada a os.getenv()",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

                    # os.environ.get(...)
                    elif func.attr == "get":
                        if isinstance(func.value, ast.Attribute) and func.value.attr == "environ":
                            if isinstance(func.value.value, ast.Name) and func.value.value.id == "os":
                                if node.args and isinstance(node.args[0], ast.Constant):
                                    severity = _classify_env_key(str(node.args[0].value))
                                else:
                                    severity = Severity.MEDIUM
                                findings.append(Finding(
                                    severity=severity,
                                    description="Se detectó llamada a os.environ.get()",
                                    filename=filename,
                                    line_number=line_num,
                                    code_snippet=snippet,
                                    analyzer_name=self.name,
                                ))

        return findings
