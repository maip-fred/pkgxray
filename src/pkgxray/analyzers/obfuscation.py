"""Analizador de técnicas de ofuscación de código."""

import ast
import re
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

_HEX_ESCAPE_PATTERN = re.compile(r"(\\x[0-9a-fA-F]{2}){10,}")


class ObfuscationAnalyzer(BaseAnalyzer):
    name = "obfuscation"
    description = "Detecta técnicas de ofuscación de código"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de patrones de ofuscación."""
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []

        for node in ast.walk(tree):
            # exec(base64.b64decode(...)) — patrón combinado = CRITICAL
            if isinstance(node, ast.Call):
                func = node.func
                line_num = node.lineno
                snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""

                # Detectar exec(base64.b64decode(...))
                if isinstance(func, ast.Name) and func.id in ("exec", "eval"):
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Call):
                            inner_func = first_arg.func
                            if isinstance(inner_func, ast.Attribute) and inner_func.attr == "b64decode":
                                findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    description="exec/eval combinado con base64.b64decode() — patrón clásico de malware",
                                    filename=filename,
                                    line_number=line_num,
                                    code_snippet=snippet,
                                    analyzer_name=self.name,
                                ))
                                continue

                # codecs.decode() con rot13 u otro encoding sospechoso
                # (base64.b64decode() aislado es muy común y legítimo; solo se reporta
                # cuando está combinado con exec/eval, que ya se capturó arriba como CRITICAL)
                if isinstance(func, ast.Attribute) and func.attr == "decode":
                    if isinstance(func.value, ast.Name) and func.value.id == "codecs":
                        encoding_arg = None
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                            encoding_arg = node.args[1].value
                        if encoding_arg and "rot" in str(encoding_arg).lower():
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                description=f"Se detectó codecs.decode() con encoding '{encoding_arg}'",
                                filename=filename,
                                line_number=line_num,
                                code_snippet=snippet,
                                analyzer_name=self.name,
                            ))

                # bytes.fromhex()
                elif isinstance(func, ast.Attribute) and func.attr == "fromhex":
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        description="Se detectó bytes.fromhex() — puede decodificar un payload oculto",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

            # Strings con muchas secuencias de escape hexadecimal (p. ej. "\x68\x65\x6c\x6c\x6f")
            elif isinstance(node, ast.Constant):
                value = node.value
                if isinstance(value, str) and len(value) > 100:
                    # Revisar el fuente original en busca de secuencias \xNN repetidas
                    line_num = getattr(node, 'lineno', 0)
                    if line_num and line_num <= len(lines):
                        line_content = lines[line_num - 1]
                        if _HEX_ESCAPE_PATTERN.search(line_content):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                description="Se detectó un string largo con escape hexadecimal — posible payload ofuscado",
                                filename=filename,
                                line_number=line_num,
                                code_snippet=line_content.strip()[:200],
                                analyzer_name=self.name,
                            ))

        return findings
