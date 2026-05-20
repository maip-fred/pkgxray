"""Analizador de patrones de acceso a variables de entorno."""

import ast
from typing import List

from pkgxray.analyzers.base import (
    BaseAnalyzer, Finding, Severity, build_parent_map, is_module_level,
)

_SENSITIVE_ENV_KEYWORDS = {
    # Cloud providers
    "AWS_SECRET", "AWS_ACCESS_KEY", "AZURE_", "GCP_", "DO_TOKEN",
    # Generic secrets
    "API_KEY", "TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY",
    # Database
    "DATABASE_URL", "MYSQL_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD", "MONGO_URI",
    # CI/CD & version control
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN",
    # Messaging & services
    "SLACK_TOKEN", "SLACK_WEBHOOK", "TWILIO_SID", "STRIPE_KEY", "SENDGRID_API_KEY",
    # AI services
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    # Auth
    "JWT_SECRET", "SESSION_SECRET", "COOKIE_SECRET",
}


def _classify_env_key(key: str) -> Severity:
    """Retorna HIGH si la clave contiene un keyword sensible, LOW si no."""
    if any(kw in key.upper() for kw in _SENSITIVE_ENV_KEYWORDS):
        return Severity.HIGH
    return Severity.LOW


def _escalate(base_severity: Severity, node, parent_map: dict) -> Severity:
    """Escala a CRITICAL si el nodo está al nivel de módulo.

    Solo se escala HIGH y MEDIUM — los accesos LOW (HOME, PATH, TERM…)
    son tan comunes que escalarlos generaría demasiado ruido.
    """
    if base_severity == Severity.LOW:
        return base_severity
    if is_module_level(node, parent_map):
        return Severity.CRITICAL
    return base_severity


class EnvAccessAnalyzer(BaseAnalyzer):
    name = "env_access"
    description = "Detecta accesos a variables de entorno"

    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree=None,
        parent_map=None,
        aliases=None,   # accepted but not used by this analyser
    ) -> List[Finding]:
        """Analiza el código fuente en busca de accesos a variables de entorno.

        Clasificación base:
          - Variable sensible conocida (AWS_SECRET, TOKEN, API_KEY…) → HIGH
          - Cualquier otra variable → LOW (HOME, PATH, TERM son legítimas)

        Escalado:
          - Llamada HIGH o MEDIUM al nivel del módulo → CRITICAL
            (se ejecuta automáticamente al importar)
          - Llamada LOW al nivel del módulo → sigue siendo LOW
        """
        if tree is None:
            tree = self._parse_ast(source_code)
        if tree is None:
            return []

        lines = source_code.splitlines()
        findings = []
        if parent_map is None:
            parent_map = build_parent_map(tree)

        for node in ast.walk(tree):
            line_num = getattr(node, 'lineno', 0)
            snippet = lines[line_num - 1].strip()[:200] if line_num and line_num <= len(lines) else ""

            # ── os.environ["KEY"] ─────────────────────────────────────────────
            if isinstance(node, ast.Subscript):
                value = node.value
                if isinstance(value, ast.Attribute) and value.attr == "environ":
                    if isinstance(value.value, ast.Name) and value.value.id == "os":
                        key_node = node.slice
                        # Python 3.8 envuelve el slice en un nodo Index
                        if hasattr(key_node, 'value') and not isinstance(key_node, ast.Constant):
                            key_node = key_node.value
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                            base_sev = _classify_env_key(key_node.value)
                        else:
                            # Acceso dinámico: no conocemos la clave
                            base_sev = Severity.MEDIUM
                        severity = _escalate(base_sev, node, parent_map)
                        findings.append(Finding(
                            severity=severity,
                            description="Se detectó acceso a os.environ",
                            filename=filename,
                            line_number=line_num,
                            code_snippet=snippet,
                            analyzer_name=self.name,
                        ))

            # ── os.getenv(...) / os.environ.get(...) ──────────────────────────
            elif isinstance(node, ast.Call):
                func = node.func
                if not isinstance(func, ast.Attribute):
                    continue

                # os.getenv("KEY") — only flag when the receiver is 'os'
                if func.attr == "getenv":
                    # Require the receiver to be 'os' to avoid false positives on
                    # config.getenv(), parser.getenv(), etc.
                    if not (isinstance(func.value, ast.Name) and func.value.id == "os"):
                        continue
                    if node.args and isinstance(node.args[0], ast.Constant):
                        base_sev = _classify_env_key(str(node.args[0].value))
                    else:
                        base_sev = Severity.MEDIUM
                    severity = _escalate(base_sev, node, parent_map)
                    findings.append(Finding(
                        severity=severity,
                        description="Se detectó llamada a os.getenv()",
                        filename=filename,
                        line_number=line_num,
                        code_snippet=snippet,
                        analyzer_name=self.name,
                    ))

                # os.environ.get("KEY")
                elif func.attr == "get":
                    if isinstance(func.value, ast.Attribute) and func.value.attr == "environ":
                        if isinstance(func.value.value, ast.Name) and func.value.value.id == "os":
                            if node.args and isinstance(node.args[0], ast.Constant):
                                base_sev = _classify_env_key(str(node.args[0].value))
                            else:
                                base_sev = Severity.MEDIUM
                            severity = _escalate(base_sev, node, parent_map)
                            findings.append(Finding(
                                severity=severity,
                                description="Se detectó llamada a os.environ.get()",
                                filename=filename,
                                line_number=line_num,
                                code_snippet=snippet,
                                analyzer_name=self.name,
                            ))

        return findings
