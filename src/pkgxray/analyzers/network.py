"""Analizador de patrones de conexiones de red y solicitudes HTTP."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
    collect_import_aliases,
)

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


def _extract_receiver_name(node) -> str:
    """Extrae el nombre del receptor de func.value en una llamada a método.

    Cubre receptores simples y encadenados:
      requests.get()       → Name('requests')            → 'requests'
      self.session.get()   → Attribute(Name('self'), 'session') → 'session'
      self.client.post()   → Attribute(Name('self'), 'client')  → 'client'
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


# HTTP client constructor names whose instances we track (#7)
_HTTP_CLIENT_CONSTRUCTORS = {
    "AsyncClient", "Client", "Session",
}


def _collect_client_var(call_node, targets, aliases: dict, out: set) -> None:
    """Adds target variable names to *out* if call_node is an HTTP client constructor.

    Recognises:  httpx.AsyncClient(), httpx.Client(), requests.Session()
    including aliases: import httpx as hx → hx.AsyncClient().
    """
    if not isinstance(call_node, ast.Call):
        return
    func = call_node.func
    if not (isinstance(func, ast.Attribute) and func.attr in _HTTP_CLIENT_CONSTRUCTORS):
        return
    if not isinstance(func.value, ast.Name):
        return
    canonical_module = aliases.get(func.value.id, func.value.id)
    if canonical_module not in _KNOWN_HTTP_RECEIVERS and canonical_module not in ("httpx", "requests"):
        return
    for target in targets:
        if isinstance(target, ast.Name):
            out.add(target.id)


class NetworkAnalyzer(BaseAnalyzer):
    name = "network"
    description = "Detecta conexiones de red y solicitudes HTTP"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,
    ) -> List[Finding]:
        """Analiza el código fuente en busca de llamadas reales de red.

        Solo reporta llamadas concretas (urlopen, requests.get, socket.connect, etc.),
        no las importaciones — importar requests o socket es legítimo en muchos paquetes.
        Las llamadas al nivel del módulo se elevan a CRITICAL porque se ejecutan
        automáticamente al importar el paquete.
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

        # #7: pre-pass — collect variable names bound to HTTP client instances
        # Handles: c = httpx.AsyncClient()  and  async with httpx.Client() as c:
        _client_vars: set = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                _collect_client_var(n.value, n.targets, aliases, _client_vars)
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                        _collect_client_var(item.context_expr, [item.optional_vars], aliases, _client_vars)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            line_num = node.lineno
            snippet = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""
            at_module = is_module_level(node, parent_map)
            suffix = " — ejecutado al nivel del módulo, corre al importar" if at_module else ""

            if isinstance(func, ast.Attribute):
                attr = func.attr

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
                    receiver = _extract_receiver_name(func.value)
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

                # get/post/put/delete/patch/head: solo si el receptor es un cliente HTTP conocido.
                # El helper _extract_receiver_name resuelve cadenas de atributos para que
                # self.session.get() también sea detectado (session ∈ _KNOWN_HTTP_RECEIVERS).
                elif attr in _HTTP_METHOD_ATTRS:
                    receiver = _extract_receiver_name(func.value)
                    # Resolve through aliases: 'req' → 'requests'
                    receiver = aliases.get(receiver, receiver)
                    if receiver in _KNOWN_HTTP_RECEIVERS or receiver in _client_vars:
                        severity = Severity.CRITICAL if at_module else Severity.HIGH
                        findings.append(Finding(
                            severity=severity,
                            description=f"Se detectó llamada HTTP '{receiver}.{attr}()' — solicitud de red explícita{suffix}",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

            # #6: ast.Name calls — detect aliased direct imports
            # e.g. from urllib.request import urlopen as fetch; fetch(url)
            elif isinstance(func, ast.Name):
                canonical = aliases.get(func.id, "")
                if not canonical:
                    continue
                func_part = canonical.split(".")[-1]
                module_name = canonical.rsplit(".", 1)[0].split(".")[-1] if "." in canonical else ""

                if func_part in _UNCONDITIONAL_CALL_ATTRS:
                    severity = Severity.CRITICAL if at_module else Severity.HIGH
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada de red '{func_part}()' (importado como '{func.id}'){suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))
                elif func_part in _HTTP_METHOD_ATTRS and module_name in _KNOWN_HTTP_RECEIVERS:
                    severity = Severity.CRITICAL if at_module else Severity.HIGH
                    findings.append(Finding(
                        severity=severity,
                        description=f"Se detectó llamada HTTP '{func.id}()' — solicitud de red explícita{suffix}",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

        return findings
