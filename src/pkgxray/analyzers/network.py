"""Analizador de patrones de conexiones de red y solicitudes HTTP."""

import ast
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level

# Métodos que solo son sospechosos si el receptor ES un objeto de red conocido.
# Evita falsos positivos en dict.get(), config.get(), etc.
_HTTP_METHOD_ATTRS = {"get", "post", "put", "delete", "patch", "head"}
_KNOWN_HTTP_RECEIVERS = {
    "requests", "httpx", "session", "Session",
    "client", "Client", "http", "https",
}

# Métodos siempre sospechosos independientemente del receptor.
_UNCONDITIONAL_CALL_ATTRS = {"urlopen", "create_connection"}

# connect() se evalúa solo si el receptor no parece ser una BD u ORM.
_SOCKET_LIKE_CALL_ATTRS = {"connect"}
_DB_RECEIVERS_EXCLUDE = {"sqlite3", "psycopg2", "engine", "conn", "db", "cursor", "pool"}


class NetworkAnalyzer(BaseAnalyzer):
    name = "network"
    description = "Detecta conexiones de red y solicitudes HTTP"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas reales de red.

        Solo reporta llamadas concretas (urlopen, requests.get, socket.connect, etc.),
        no las importaciones — importar requests o socket es legítimo en muchos paquetes.
        Las llamadas al nivel del módulo se elevan a CRITICAL porque se ejecutan
        automáticamente al importar el paquete.
        """
        tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        parent_map = build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            attr = func.attr
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            # urlopen, create_connection: siempre sospechosos
            if attr in _UNCONDITIONAL_CALL_ATTRS:
                severity = Severity.CRITICAL if at_module else Severity.HIGH
                findings.append(Finding(
                    severity=severity,
                    description=f"Se detectó llamada de red '{attr}()'{suffix}",
                    filename=filename,
                    line_number=line_num,
                    code_snippet=snippet,
                    analyzer_name=self.name,
                ))

            # connect(): solo si el receptor no es claramente una BD
            elif attr in _SOCKET_LIKE_CALL_ATTRS:
                receiver = func.value.id if isinstance(func.value, ast.Name) else ""
                if receiver not in _DB_RECEIVERS_EXCLUDE:
                    severity = Severity.CRITICAL if at_module else Severity.HIGH
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada de red '{attr}()' — posible conexión de socket{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

            # get/post/put/delete/patch/head: solo si el receptor es un cliente HTTP conocido
            # Esto evita marcar dict.get(), config.get(), etc.
            elif attr in _HTTP_METHOD_ATTRS:
                receiver = func.value.id if isinstance(func.value, ast.Name) else ""
                if receiver in _KNOWN_HTTP_RECEIVERS:
                    severity = Severity.CRITICAL if at_module else Severity.HIGH
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada HTTP '{receiver}.{attr}()' — solicitud de red explícita{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

        return findings
