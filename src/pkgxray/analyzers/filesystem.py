"""Analizador de patrones sospechosos de acceso al sistema de archivos."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

_SENSITIVE_PATHS = {
    "/etc/passwd": Severity.CRITICAL,
    "/etc/shadow": Severity.CRITICAL,
    "~/.ssh/": Severity.CRITICAL,
    "/.ssh/": Severity.CRITICAL,
    "~/.aws/": Severity.CRITICAL,
    "/.aws/": Severity.CRITICAL,
    "~/.bashrc": Severity.HIGH,
    "~/.profile": Severity.HIGH,
    "~/.zshrc": Severity.HIGH,
    "/tmp/": Severity.MEDIUM,
}

_DESTRUCTIVE_ATTRS = {
    "remove": Severity.HIGH,
    "unlink": Severity.HIGH,
    "rmtree": Severity.HIGH,
}


class FilesystemAnalyzer(BaseAnalyzer):
    name = "filesystem"
    description = "Detecta accesos sospechosos al sistema de archivos"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de patrones de acceso sospechoso al sistema de archivos.

        Detecta llamadas destructivas (os.remove, shutil.rmtree) y referencias a rutas
        sensibles (/etc/passwd, ~/.ssh/, ~/.aws/, etc.) en el código fuente.
        No reporta open() en modo escritura porque es demasiado común en paquetes legítimos.
        """
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []

        for node in ast.walk(tree):
            # A) Llamadas destructivas: os.remove, os.unlink, shutil.rmtree
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in _DESTRUCTIVE_ATTRS:
                    snippet = lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        severity=_DESTRUCTIVE_ATTRS[func.attr],
                        description=f"Se detectó llamada destructiva al sistema de archivos '{func.attr}()'",
                        filename=filename,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

            # B) Strings con rutas sensibles
            elif isinstance(node, ast.Constant) and isinstance(node.s if hasattr(node, 's') else node.value, str):
                value = node.value if hasattr(node, 'value') else node.s
                if isinstance(value, str):
                    for path, severity in _SENSITIVE_PATHS.items():
                        if path in value:
                            line_num = getattr(node, 'lineno', 0)
                            snippet = lines[line_num - 1].strip()[:200] if line_num and line_num <= len(lines) else value[:200]
                            findings.append(Finding(
                                severity=severity,
                                description=f"Se encontró la ruta sensible '{path}' en el código",
                                filename=filename,
                                line_number=line_num,
                                code_snippet=snippet,
                                analyzer_name=self.name,
                            ))

        return findings
