"""Modelos de datos base y analizador abstracto para pkgxray."""

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def collect_import_aliases(tree: ast.AST) -> dict:
    """Returns a dict mapping local alias names to their canonical module/symbol.

    Handles:
      import subprocess as sp              → {'sp': 'subprocess'}
      import os as operating_system        → {'operating_system': 'os'}
      from subprocess import run           → {'run': 'subprocess.run'}
      from subprocess import Popen as P    → {'P': 'subprocess.Popen'}
      from requests import get             → {'get': 'requests.get'}
    """
    aliases: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                aliases[local_name] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def build_parent_map(tree) -> dict:
    """Devuelve un dict que mapea id(nodo_hijo) → nodo_padre para todo el AST."""
    parent_map: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


def is_module_level(node, parent_map: dict) -> bool:
    """Retorna True si *node* no está anidado dentro de ninguna función.

    Las llamadas a nivel de módulo (incluyendo cuerpos de clase) se ejecutan
    automáticamente al importar el paquete — sin que el usuario las invoque —
    lo que las hace mucho más peligrosas.

    ClassDef NO es barrera: el cuerpo de una clase se ejecuta en tiempo de
    importación, igual que el código suelto a nivel de módulo.
    """
    current_id = id(node)
    while current_id in parent_map:
        parent = parent_map[current_id]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        current_id = id(parent)
    return True


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    severity: Severity
    description: str
    filename: str
    line_number: int
    code_snippet: str
    analyzer_name: str


class BaseAnalyzer(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def analyze(
        self,
        source_code: str,
        filename: str,
        *,
        tree: Optional[ast.AST] = None,
        parent_map: Optional[dict] = None,
        aliases: Optional[dict] = None,
    ) -> list:
        """Analiza el código fuente y retorna una lista de objetos Finding.

        Si el llamador ya ha parseado el AST y construido el parent_map, puede
        pasarlos para evitar trabajo duplicado.  Ambos parámetros son opcionales
        — el analizador los construirá por su cuenta si no se proporcionan.

        If the caller has already collected the alias map, pass it here to avoid
        rebuilding it.  Analysers should call collect_import_aliases(tree) as a
        fallback when aliases is None.
        """
        ...

    def _parse_ast(self, source_code: str):
        """Parsea el código fuente a un AST; retorna None si falla."""
        try:
            return ast.parse(source_code)
        except SyntaxError:
            return None
        except Exception:
            return None


@dataclass
class ExtractedFile:
    filename: str
    content: str
    is_setup: bool = False   # True solo para setup.py → SetupScriptAnalyzer
    is_config: bool = False  # True para pyproject.toml / setup.cfg → ConfigFileAnalyzer


@dataclass
class ScanResult:
    package_name: str
    version: str
    scan_date: str
    findings: list
    risk_score: int
    risk_level: str
    files_analyzed: int
    summary: dict
    skipped_files: list = field(default_factory=list)
    # Each entry: {"filename": str, "reason": "syntax_error" | "parse_error"}
    binary_files_found: int = 0
