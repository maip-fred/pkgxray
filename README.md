![PyPI](https://img.shields.io/pypi/v/pkgxray)
![Python](https://img.shields.io/pypi/pyversions/pkgxray)
![License](https://img.shields.io/pypi/l/pkgxray)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/maip-fred/pkgxray/blob/main/notebooks/pkgxray_tutorial.ipynb)

# 🔬 pkgxray

**Analiza paquetes de PyPI en busca de comportamiento sospechoso antes de instalarlos.**

Cuando ejecutas `pip install un-paquete`, confías ciegamente en que el código es seguro.
pkgxray descarga el paquete **sin instalarlo**, extrae el código fuente y ejecuta
8 analizadores especializados basados en AST para detectar patrones maliciosos —
todo esto antes de que una sola línea del paquete se ejecute en tu máquina.

---

## Características

pkgxray detecta **8 categorías** de comportamiento sospechoso:

| # | Analizador | Qué detecta | Severidad máxima |
|---|------------|-------------|-----------------|
| 1 | `code_exec` | Llamadas a `eval()`, `exec()`, `compile()` — CRITICAL si están al nivel del módulo | CRITICAL |
| 2 | `network` | `urlopen()`, `requests.get()`, `socket.connect()` — CRITICAL si están al nivel del módulo | CRITICAL |
| 3 | `filesystem` | Borrado de archivos (`os.remove`, `shutil.rmtree`), rutas sensibles (`/etc/passwd`, `~/.ssh/`) | CRITICAL |
| 4 | `env_access` | Acceso a variables de entorno (API keys, tokens, contraseñas) | HIGH |
| 5 | `subprocess` | `subprocess.Popen()`, `os.system()` — CRITICAL si están al nivel del módulo | CRITICAL |
| 6 | `obfuscation` | `exec(base64.b64decode(...))`, strings con escape hexadecimal, `codecs.decode()` rot13 | CRITICAL |
| 7 | `setup_scripts` | Hooks post-instalación en `setup.py` que ejecutan código al instalar | CRITICAL |
| 8 | `dynamic_imports` | `__import__()`, `importlib.import_module()` con argumentos dinámicos | HIGH |

---

## Instalación

```bash
pip install pkgxray
```

---

## Inicio rápido

### Interfaz de línea de comandos

```bash
# Analizar un paquete (salida en terminal con colores)
pkgxray scan requests

# Obtener salida en JSON
pkgxray scan requests --format json

# Guardar reporte HTML en archivo
pkgxray scan requests --format html -o reporte.html

# Analizar una versión específica
pkgxray scan requests --version 2.28.0
```

### API de Python

```python
from pkgxray import scan
from pkgxray.reporter import generate_report

# Analizar un paquete
result = scan("requests")

print(f"Puntaje de riesgo: {result.risk_score}/100")
print(f"Nivel de riesgo: {result.risk_level}")
print(f"Archivos analizados: {result.files_analyzed}")
print(f"Hallazgos totales: {len(result.findings)}")

# Inspeccionar hallazgos individuales
for finding in result.findings:
    print(f"[{finding.severity.value.upper()}] {finding.analyzer_name}")
    print(f"  {finding.filename}:{finding.line_number}")
    print(f"  {finding.description}")

# Exportar como JSON
json_report = generate_report(result, format="json")

# Guardar reporte HTML
generate_report(result, format="html", output_path="reporte.html")
```

---

## Docker

```bash
# Ejecutar los tests dentro de Docker
docker-compose run test

# Analizar el paquete "requests"
docker-compose run scan

# Analizar "requests" y obtener salida JSON
docker-compose run scan-json
```

O construir y ejecutar directamente:

```bash
docker build -t pkgxray .
docker run pkgxray scan requests
docker run pkgxray scan requests --format json
```

---

## Cómo funciona

```
pkgxray scan <paquete>
      |
      v
1. DESCARGA   -> Consulta la API JSON de PyPI
                Descarga el .tar.gz o .whl (sin instalarlo)
      |
      v
2. EXTRACCIÓN -> Descomprime el archivo
                Extrae todos los archivos .py (incluyendo setup.py)
      |
      v
3. ANÁLISIS   -> Ejecuta 8 analizadores basados en AST en cada archivo
                El parseo AST es robusto: no puede evadirse renombrando variables
      |
      v
4. PUNTUACIÓN -> Pondera hallazgos por severidad:
                LOW=1  MEDIUM=3  HIGH=7  CRITICAL=15
                Puntaje final: 0–100
      |
      v
5. REPORTE    -> Salida en terminal (con colores), JSON o HTML
```

**¿Por qué AST en lugar de regex?**
- Entiende la estructura del código, no solo el texto
- Más difícil de evadir: renombrar una variable no lo engaña
- Sin dependencias adicionales — usa el módulo `ast` integrado de Python

**Llamadas al nivel del módulo**
pkgxray distingue entre código que se ejecuta automáticamente al importar el paquete (nivel
de módulo) y código dentro de funciones que requiere invocación explícita. Las llamadas
peligrosas al nivel del módulo se elevan automáticamente a CRITICAL porque se ejecutarían
en el momento en que el usuario hace `import paquete` — sin ninguna acción adicional.

---

## Analizadores

| Analizador | Descripción | Rango de severidad |
|------------|-------------|-------------------|
| `code_exec` | Detecta `eval()`, `exec()`, `compile()`. Si la llamada está al nivel del módulo (se ejecuta al importar) → CRITICAL | HIGH – CRITICAL |
| `network` | Detecta `urlopen()`, `requests.get()`, `socket.connect()` y similares. Nivel de módulo → CRITICAL | HIGH – CRITICAL |
| `filesystem` | Detecta `os.remove()`, `shutil.rmtree()`, y referencias a rutas sensibles (`/etc/passwd`, `~/.ssh/`, `~/.aws/`) | HIGH – CRITICAL |
| `env_access` | Detecta `os.environ`, `os.getenv()`, acceso a API keys, tokens y contraseñas | LOW – HIGH |
| `subprocess` | Detecta `subprocess.Popen()`, `subprocess.run()`, `os.system()`, `os.execvp()`. Nivel de módulo → CRITICAL | HIGH – CRITICAL |
| `obfuscation` | Detecta `exec(base64.b64decode(...))`, `bytes.fromhex()`, strings con secuencias hexadecimales, `codecs.decode()` rot13 | MEDIUM – CRITICAL |
| `setup_scripts` | Detecta hooks post-instalación en `setup.py` que sobreescriben `install.run()`, e importaciones de módulos de red | HIGH – CRITICAL |
| `dynamic_imports` | Detecta `__import__()` e `importlib.import_module()` con argumentos dinámicos | MEDIUM – HIGH |

---

## Desarrollo

```bash
# Clonar e instalar en modo desarrollo
git clone https://github.com/maip-fred/pkgxray.git
cd pkgxray
pip install -e ".[dev]"

# Ejecutar tests unitarios (rápidos, sin red)
pytest tests/ -v -m "not slow"

# Ejecutar todos los tests incluyendo los de integración
pytest tests/ -v

# Ejecutar con cobertura
pytest tests/ --cov=pkgxray --cov-report=html -m "not slow"
```

---

## ¿Por qué no usar pip-audit?

| Herramienta | Qué hace |
|-------------|---------|
| `pip-audit` / `safety` | Busca **CVEs conocidos** — vulnerabilidades ya reportadas |
| `bandit` | Analiza **tu código**, no paquetes de terceros antes de instalarlos |
| **`pkgxray`** | **Análisis de comportamiento** de paquetes de terceros **antes** de instalarlos |

pkgxray es la única herramienta instalable con pip que realiza análisis AST estático
sobre paquetes de PyPI antes de que los instales.

---

## Licencia

MIT — ver [LICENSE](LICENSE)
