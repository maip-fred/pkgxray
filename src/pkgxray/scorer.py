"""Sistema de puntuación de riesgo para los resultados de escaneo de pkgxray."""

from collections import defaultdict
from typing import List, Tuple

from pkgxray.analyzers.base import Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 15,
}

# Contribución máxima de cualquier analizador individual al puntaje final.
# Esto evita que un solo analizador domine el score cuando hay muchas repeticiones
# del mismo patrón legítimo (p.ej. una librería CLI que lee 20 variables de entorno).
# El score final refleja cuántos *tipos* de comportamiento sospechoso hay,
# no cuántas veces aparece uno solo.
MAX_SCORE_PER_ANALYZER = 20


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    """Calcula un puntaje de riesgo de 0 a 100 a partir de una lista de hallazgos.

    El puntaje se calcula sumando los pesos por severidad de cada analizador,
    pero limitando la contribución de cada analizador a MAX_SCORE_PER_ANALYZER
    para evitar que patrones repetitivos y legítimos inflen artificialmente el score.

    Args:
        findings: Lista de objetos Finding producidos por los analizadores.

    Returns:
        Tupla (puntaje, nivel) donde nivel es uno de:
        "LOW", "MODERATE", "HIGH", "CRITICAL".
    """
    if not findings:
        return 0, "LOW"

    # Agrupar peso por analizador y aplicar el tope individual
    weight_by_analyzer: dict = defaultdict(int)
    for f in findings:
        weight_by_analyzer[f.analyzer_name] += SEVERITY_WEIGHTS.get(f.severity, 0)

    capped_total = sum(min(w, MAX_SCORE_PER_ANALYZER) for w in weight_by_analyzer.values())
    score = min(100, capped_total)

    if score <= 20:
        level = "LOW"
    elif score <= 40:
        level = "MODERATE"
    elif score <= 70:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level


def get_summary(findings: List[Finding]) -> dict:
    """Cuenta los hallazgos por nivel de severidad.

    Args:
        findings: Lista de objetos Finding.

    Returns:
        Diccionario con conteos por severidad y un total, p. ej.:
        {"low": 2, "medium": 5, "high": 1, "critical": 0, "total": 8}
    """
    summary = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}
    for f in findings:
        key = f.severity.value
        if key in summary:
            summary[key] += 1
    summary["total"] = len(findings)
    return summary
