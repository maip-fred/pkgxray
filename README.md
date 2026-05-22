![PyPI](https://img.shields.io/pypi/v/pkgxray)
![Python](https://img.shields.io/pypi/pyversions/pkgxray)
![License](https://img.shields.io/pypi/l/pkgxray)
![Tests](https://github.com/maip-fred/pkgxray/actions/workflows/publish.yml/badge.svg)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/maip-fred/pkgxray/blob/main/notebooks/pkgxray_v1_walkthrough.ipynb)

# pkgxray

**Analiza paquetes de PyPI en busca de comportamiento malicioso antes de instalarlos.**

pkgxray descarga un paquete directamente desde PyPI (o un registro privado), extrae su código fuente y lo analiza estáticamente mediante 10 analizadores especializados basados en AST. Produce un reporte con hallazgos clasificados por severidad y un puntaje de riesgo de 0 a 100, sin instalar nada en tu entorno.

```
$ pkgxray scan requests
Package : requests 2.32.3
Risk    : MODERATE (score: 22/100)

Findings
────────────────────────────────────────────
HIGH   network     urllib3/connectionpool.py:287  urllib.request.urlopen() detectado
...
```

---

## Índice

- [Por qué pkgxray](#por-qué-pkgxray)
- [Instalación](#instalación)
- [Docker](#docker)
- [Uso desde la CLI](#uso-desde-la-cli)
- [Uso como librería Python](#uso-como-librería-python)
- [Cómo funciona — arquitectura](#cómo-funciona--arquitectura)
- [Los 10 analizadores](#los-10-analizadores)
- [Sistema de puntuación](#sistema-de-puntuación)
- [Caché en disco](#caché-en-disco)
- [Soporte para registros privados](#soporte-para-registros-privados)
- [Formatos de salida](#formatos-de-salida)
- [Uso en pipelines CI/CD](#uso-en-pipelines-cicd)
- [Evolución del proyecto](#evolución-del-proyecto)
- [Historial de versiones](#historial-de-versiones)

---

## Por qué pkgxray

Los ataques de supply chain contra el ecosistema PyPI son cada vez más frecuentes. Paquetes con nombres similares a librerías populares (*typosquatting*), versiones comprometidas que añaden código malicioso en `setup.py`, o paquetes que roban variables de entorno durante la instalación: todos estos vectores son reales y documentados.

Las alternativas existentes al momento de construir pkgxray:

| Herramienta | Limitación |
|---|---|
| `pip audit` | Solo verifica CVEs conocidos, no comportamiento |
| Snyk / Dependabot | Requieren suscripción, no análisis de comportamiento |
| Revisión manual | No escala, difícil de sistematizar |
| Bandit | Analiza tu propio código, no paquetes de terceros |

pkgxray cubre el espacio vacío: **análisis de comportamiento antes de instalar**, sin costo, sin cuenta, sin instalar el paquete objetivo.

---

## Instalación

```bash
pip install pkgxray
```

**Requisitos:** Python 3.9 o superior.

**Dependencias automáticas:**
- `click >= 8.0` — interfaz de línea de comandos
- `rich >= 13.0` — reportes con color en terminal
- `tomli >= 2.0` — soporte TOML en Python < 3.11

---

## Uso desde la CLI

### Escaneo básico

```bash
pkgxray scan <nombre-del-paquete>
```

```bash
pkgxray scan requests
pkgxray scan numpy==1.26.0
pkgxray scan boto3 --version 1.34.0
```

### Todas las opciones

```
pkgxray scan [OPCIONES] PACKAGE_NAME

Opciones:
  -v, --version TEXT        Versión específica a analizar (default: última)
  -f, --format [terminal|json|html]
                            Formato de salida (default: terminal)
  -o, --output PATH         Guardar reporte en archivo
  --fail-above INTEGER      Salir con código 1 si risk_score >= N
  --verbose                 Activa logging detallado (útil para debug)
  --index-url TEXT          URL de registro PyPI privado
  --help                    Muestra esta ayuda
```

### Ejemplos prácticos

```bash
# Analizar la última versión
pkgxray scan paramiko

# Analizar versión específica
pkgxray scan boto3 --version 1.34.0

# Guardar reporte HTML
pkgxray scan requests --format html --output report.html

# Guardar reporte JSON
pkgxray scan flask --format json --output result.json

# CI/CD: falla si el puntaje supera 60
pkgxray scan some-package --fail-above 60 && pip install some-package

# Registro privado
pkgxray scan mi-paquete-interno --index-url https://pypi.miempresa.com/simple/

# Debug detallado
pkgxray scan sospechoso --verbose

# Limpiar caché en disco
pkgxray clear-cache
```

---

## Uso como librería Python

pkgxray puede usarse programáticamente en scripts o notebooks:

```python
import pkgxray

# Escanear un paquete
result = pkgxray.scan("requests")

print(result.package_name)       # "requests"
print(result.version)            # "2.32.3"
print(result.risk_score)         # 22
print(result.risk_level)         # "MODERATE"
print(result.files_analyzed)     # 147
print(result.binary_files_found) # 3

# Iterar sobre hallazgos
for finding in result.findings:
    print(finding.severity.value)   # "high"
    print(finding.analyzer_name)    # "network"
    print(finding.filename)         # "urllib3/connectionpool.py"
    print(finding.line_number)      # 287
    print(finding.description)      # "urllib.request.urlopen() detectado"
    print(finding.code_snippet)     # "response = urlopen(url)"

# Resumen por severidad
print(result.summary)
# {"low": 2, "medium": 5, "high": 8, "critical": 0, "total": 15}

# Archivos que no pudieron analizarse
for skipped in result.skipped_files:
    print(skipped["filename"], skipped["reason"])

# Escanear versión específica con registro privado
result = pkgxray.scan(
    "mi-paquete",
    version="2.1.0",
    registry_url="https://pypi.miempresa.com/simple/"
)

# Limpiar caché de sesión (en memoria)
pkgxray.clear_cache()

# Limpiar caché de disco
count = pkgxray.clear_disk_cache()
print(f"Eliminados {count} archivos de caché")
```

### Tipos exportados

```python
from pkgxray import ScanResult, Finding, Severity

# Severity es un Enum
Severity.LOW      # "low"
Severity.MEDIUM   # "medium"
Severity.HIGH     # "high"
Severity.CRITICAL # "critical"
```

---

## Cómo funciona — arquitectura

pkgxray implementa un pipeline secuencial de 5 etapas:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐    ┌──────────┐    ┌──────────┐
│  Descarga   │ -> │  Extracción │ -> │  Análisis AST       │ -> │  Scorer  │ -> │  Reporte │
│ downloader  │    │  extractor  │    │  10 analizadores    │    │ scorer   │    │ reporter │
└─────────────┘    └─────────────┘    └─────────────────────┘    └──────────┘    └──────────┘
```

### 1. Descarga (`downloader.py`)

- Consulta la API JSON de PyPI (o el registro privado configurado)
- Valida la URL del registro (solo `http://` y `https://`; rechaza `file://`, `ftp://` y otras para evitar SSRF)
- Selecciona la distribución en orden de preferencia: sdist (`.tar.gz`) > wheel universal > cualquier wheel disponible
- Descarga el archivo y verifica su integridad mediante SHA-256

### 2. Extracción (`extractor.py`)

- Descomprime el archivo `.tar.gz` o `.whl` en un directorio temporal
- Valida cada ruta contra *path traversal* (zip-slip): rechaza rutas con `..` o absolutas
- Limita el tamaño de archivo a **5 MB** por archivo para evitar OOM
- Extrae archivos `.py`, `pyproject.toml` y `setup.cfg`
- Cuenta archivos binarios (`.so`, `.pyd`, `.dll`, `.dylib`) pero no los analiza

### 3. Análisis AST (`analyzers/`)

- Parsea el AST de cada archivo Python **una sola vez**
- Construye el `parent_map` y colecta `import_aliases` una sola vez, compartidos entre todos los analizadores
- Ejecuta los 10 analizadores en secuencia; cada uno reutiliza el AST ya parseado
- Los fallos individuales de un analizador se loguean pero no abortan el escaneo

### 4. Puntuación (`scorer.py`)

- Suma pesos por severidad (LOW=1, MEDIUM=3, HIGH=7, CRITICAL=15)
- Aplica un tope (*cap*) por analizador para evitar que un solo analizador domine
- Aplica bonificaciones por combinaciones de analizadores peligrosas
- Asigna nivel cualitativo: LOW / MODERATE / HIGH / CRITICAL

### 5. Caché de dos niveles

- **En sesión:** resultados en memoria (dict) para versiones pinned; evita re-descargar si se llama `scan()` dos veces en el mismo proceso
- **En disco:** resultados persistentes entre sesiones, indexados por SHA-256 del archivo descargado; LRU eviction cuando supera 200 entradas

---

## Los 10 analizadores

### 1. `code_exec` — Ejecución dinámica de código

Detecta patrones de ejecución de código arbitrario.

**Qué detecta:**

| Patrón | Severidad base |
|--------|---------------|
| `exec(payload)` | CRITICAL |
| `eval(expression)` | HIGH |
| `compile(src, ...)` | HIGH |
| `ctypes.CDLL("lib.so")` | CRITICAL |
| `ctypes.cdll.LoadLibrary(...)` | CRITICAL |
| `e = exec; e(payload)` (alias de variable) | CRITICAL/HIGH |
| `__builtins__["exec"](payload)` | CRITICAL |
| `vars()["eval"](expression)` | HIGH |
| `getattr(__builtins__, "exec")(payload)` | CRITICAL |

Los dos últimos grupos (acceso vía subscript y `getattr`) son técnicas de ofuscación que evaden detección naive. pkgxray v1.0.0 los detecta correctamente.

**Escalado:** Cualquier hallazgo a nivel de módulo (fuera de función) sube a CRITICAL, porque se ejecuta al hacer `import`.

---

### 2. `subprocess` — Ejecución de comandos del sistema

Detecta llamadas que ejecutan procesos externos o comandos shell.

| Patrón | Severidad base |
|--------|---------------|
| `subprocess.Popen(cmd)` | CRITICAL |
| `os.system(cmd)` | CRITICAL |
| `os.popen(cmd)` | CRITICAL |
| `os.execvp(...)`, `os.execv(...)` | CRITICAL |
| `os.spawnl(...)` y 7 variantes | CRITICAL |
| `pty.spawn(...)` | CRITICAL |
| `asyncio.create_subprocess_shell(...)` | CRITICAL |
| `subprocess.run(cmd)`, `subprocess.call(cmd)` | HIGH |
| `subprocess.check_output(cmd)` | HIGH |
| `asyncio.create_subprocess_exec(...)` | HIGH |
| `os.startfile(path)` | HIGH |

Solo se reportan **llamadas reales**, no importaciones. Tener `import subprocess` en un archivo es legítimo.

---

### 3. `network` — Conexiones de red

Detecta solicitudes HTTP/HTTPS y conexiones de red realizadas durante la importación o instalación del paquete.

| Patrón | Severidad base |
|--------|---------------|
| `urllib.request.urlopen(url)` | HIGH/CRITICAL |
| `socket.create_connection(...)` | HIGH/CRITICAL |
| `requests.get(url)`, `.post()`, `.put()` | HIGH/CRITICAL |
| `httpx.get(url)`, `.post()`, etc. | HIGH/CRITICAL |
| `session.get(url)` (instancia HTTP rastreada) | HIGH/CRITICAL |
| `client.post(url)` (instancia HTTP rastreada) | HIGH/CRITICAL |
| `socket.connect(addr)` | HIGH/CRITICAL |

El analizador rastrea variables: si `client = httpx.AsyncClient()`, entonces `client.get(url)` se detecta correctamente. También resuelve aliases de importación.

---

### 4. `obfuscation` — Ofuscación de código

Detecta técnicas usadas para ocultar payloads maliciosos.

| Patrón | Severidad |
|--------|-----------|
| `exec(base64.b64decode(payload))` | CRITICAL |
| `eval(base64.b64decode(payload))` | CRITICAL |
| `exec(compile(base64.b64decode(...)))` | CRITICAL |
| Variable con b64decode, luego exec de esa variable | CRITICAL |
| `codecs.decode(data, "rot13")` | MEDIUM |
| `bytes.fromhex(hex_string)` | MEDIUM |
| String largo con muchas secuencias `\xNN` (> 100 chars) | HIGH |

**Importante:** `base64.b64decode()` aislado **no** se reporta, porque es estándar para manejo de imágenes, auth HTTP básica y certificados TLS.

---

### 5. `filesystem` — Accesos sospechosos al sistema de archivos

Detecta operaciones destructivas y accesos a rutas sensibles del sistema.

**Operaciones destructivas:**

| Patrón | Severidad |
|--------|-----------|
| `os.remove(path)` | HIGH/CRITICAL |
| `Path.unlink()` | HIGH/CRITICAL |
| `shutil.rmtree(path)` | HIGH/CRITICAL |

`remove()` y `unlink()` solo se reportan si el receptor es `os`, `pathlib` o `Path`, evitando falsos positivos con `list.remove(x)` o `set.remove(x)`.

**Rutas sensibles:**

| Ruta | Severidad |
|------|-----------|
| `/etc/passwd`, `/etc/shadow` | CRITICAL |
| `~/.ssh/`, `~/.aws/`, `~/.kube/config` | CRITICAL |
| `~/.docker/config.json`, `~/.config/gcloud/` | HIGH |
| `~/.azure/`, `~/.gnupg/`, `~/.git-credentials` | HIGH |
| `~/.npmrc`, `~/.pypirc` | HIGH |
| `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` | HIGH |
| `/tmp/` | MEDIUM |

---

### 6. `env_access` — Acceso a variables de entorno

Detecta lectura de variables de entorno, con especial atención a variables que contienen credenciales.

| Patrón | Severidad base |
|--------|---------------|
| `os.environ["AWS_SECRET_KEY"]` (variable sensible) | HIGH |
| `os.getenv("GITHUB_TOKEN")` (variable sensible) | HIGH |
| `os.environ.get("DATABASE_URL")` (variable sensible) | HIGH |
| `os.getenv(variable_dinamica)` (sin literal constante) | MEDIUM |
| `os.environ["HOME"]` (variable no sensible) | LOW |

**Variables clasificadas como sensibles:**
- Credenciales cloud: `AWS_SECRET`, `AWS_ACCESS_KEY`, `AZURE_`, `GCP_`, `DO_TOKEN`
- Tokens de servicios: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK`, `STRIPE_KEY`, `TWILIO_SID`, `SENDGRID_API_KEY`
- APIs de IA: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- Bases de datos: `DATABASE_URL`, `MYSQL_PASSWORD`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MONGO_URI`
- Secretos genéricos: `API_KEY`, `TOKEN`, `PASSWORD`, `SECRET`, `PRIVATE_KEY`
- Auth: `JWT_SECRET`, `SESSION_SECRET`, `COOKIE_SECRET`

**Escalado:** Hallazgos HIGH o MEDIUM a nivel de módulo suben a CRITICAL (se roban las credenciales al importar).

---

### 7. `dynamic_imports` — Importaciones dinámicas

Detecta carga dinámica de módulos, que puede usarse para cargar código arbitrario en tiempo de ejecución.

| Patrón | Severidad |
|--------|-----------|
| `__import__("json")` (argumento estático) | MEDIUM |
| `__import__(user_input)` (argumento dinámico) | HIGH |
| `importlib.import_module("módulo")` (estático) | MEDIUM |
| `importlib.import_module(variable)` (dinámico) | HIGH |
| `importlib.util.spec_from_file_location(...)` | HIGH/CRITICAL |

El analizador resuelve aliases: `import importlib as il; il.import_module(x)` se detecta correctamente. Solo reporta si el receptor se resuelve efectivamente como `importlib`.

---

### 8. `setup_scripts` — Hooks de instalación maliciosos

Especializado en `setup.py`. Detecta patrones que se ejecutan **automáticamente** durante `pip install`, sin intervención del usuario.

**Clases con hooks peligrosos:**

Cualquier clase que herede de `install`, `develop`, `egg_info`, `sdist`, `build_py` o `build_ext` y defina los métodos `run()` o `__init__()` se reporta como CRITICAL, porque `pip` invoca esos métodos durante la instalación.

**Importaciones inusuales en setup.py:**

| Módulo importado | Severidad |
|-----------------|-----------|
| `subprocess`, `socket`, `urllib`, `requests`, `httpx` | HIGH |

**Llamadas peligrosas en setup.py:**

| Patrón | Severidad |
|--------|-----------|
| `eval(...)`, `exec(...)` | CRITICAL |
| `urlopen(...)`, `urlretrieve(...)` | CRITICAL |
| `os.system(...)`, `os.popen(...)` | CRITICAL |
| `subprocess.Popen(...)` | CRITICAL |

---

### 9. `config_files` — Configuración sospechosa en TOML/CFG

Analiza `pyproject.toml` y `setup.cfg` en busca de configuraciones que puedan ejecutar código durante la instalación.

**En `pyproject.toml`:**

| Sección | Qué busca | Severidad |
|---------|-----------|-----------|
| `[build-system].requires` | Dependencias de build inusuales (`requests`, `httpx`, `boto3`, `paramiko`...) | HIGH |
| `[project.scripts]` / `[project.entry-points]` | Entrypoints que contienen comandos shell (`curl`, `bash`, `wget`, `nc`, `python -c`, `eval`) en lugar de referencias Python `module:function` | CRITICAL |
| `[tool.hatch.hooks]` y similares | Post-install hooks declarados | MEDIUM |

**En `setup.cfg`:**

| Sección | Qué busca | Severidad |
|---------|-----------|-----------|
| `[options].install_requires` | Dependencias de red inusuales | MEDIUM |
| `[options.entry_points]` | Shell commands disfrazados de entrypoints | CRITICAL |

Un entrypoint Python válido sigue el patrón `module:function`; cualquier cosa que contenga una keyword de shell y no siga ese patrón se reporta.

---

### 10. `process_spawn` — Spawn de procesos con targets peligrosos *(nuevo en v1.0.0)*

Este analizador cierra una brecha importante: los analizadores de `subprocess` detectan llamadas directas como `os.system("cmd")`, pero no detectan cuando la función peligrosa se **pasa como referencia** a un lanzador de procesos o hilos, evadiendo la detección.

**Patrones detectados:**

```python
# Process/Thread con target peligroso
multiprocessing.Process(target=os.system, args=("rm -rf /",))
threading.Thread(target=subprocess.Popen, args=(["cmd"],))

# Executors con callable peligroso
executor.submit(os.system, "cmd")
executor.map(subprocess.run, commands)
```

**Funciones detectadas como target peligrosas:**

Del módulo `os`: `system`, `popen`, `execvp`, `execv`, `spawnl`, `spawnle`, `spawnlp`, `spawnlpe`, `spawnv`, `spawnve`, `spawnvp`, `spawnvpe`, `startfile`

Del módulo `subprocess`: `run`, `call`, `Popen`, `check_output`, `check_call`, `getoutput`, `getstatusoutput`

El analizador resuelve aliases de importación: `import os as operating_system; Process(target=operating_system.system)` es detectado.

---

## Sistema de puntuación

### Pesos por severidad

| Severidad | Puntos por hallazgo |
|-----------|---------------------|
| LOW | 1 |
| MEDIUM | 3 |
| HIGH | 7 |
| CRITICAL | 15 |

### Topes por analizador

Para evitar que un solo analizador con muchos hallazgos domine el puntaje total:

| Analizador | Tope (pts) | Razón |
|------------|-----------|-------|
| `obfuscation` | 20 | Alta confianza de malicia |
| `setup_scripts` | 20 | Vector de ataque conocido |
| `code_exec` | 15 | Sospechoso pero con usos legítimos |
| `config_files` | 15 | Herramientas de build complejas |
| `process_spawn` | 12 | Nuevo, calibración conservadora |
| `subprocess` | 12 | Común en herramientas de build legítimas |
| `filesystem` | 12 | Operaciones de archivo normales |
| `network` | 8 | Normal en librerías HTTP |
| `dynamic_imports` | 6 | Usado en sistemas de plugins |
| `env_access` | 5 | Ubicuo en CLIs y herramientas |

### Bonificaciones por combinaciones peligrosas

Cuando múltiples analizadores detectan hallazgos simultáneamente, el riesgo combinado es mayor que la suma de sus partes:

| Combinación | Bonificación | Por qué es peligrosa |
|-------------|-------------|---------------------|
| `env_access` + `network` | +25 pts | Roba credenciales y las exfiltra por red |
| `obfuscation` + `code_exec` | +20 pts | Payload ofuscado que se ejecuta |
| `process_spawn` + `env_access` | +15 pts | Roba credenciales y las procesa en proceso hijo |
| `network` + `subprocess` | +10 pts | Descarga y ejecuta código externo |
| `setup_scripts` + `subprocess` | +10 pts | Hook de instalación ejecuta shell |
| `process_spawn` + `network` | +10 pts | Conecta a red en proceso hijo separado |

El combo `env_access + network` requiere que ambos lados tengan al menos un hallazgo CRITICAL para activarse.

### Niveles de riesgo

| Score | Nivel | Interpretación |
|-------|-------|---------------|
| 0 – 15 | LOW | Comportamiento normal, sin señales de alerta |
| 16 – 35 | MODERATE | Patrones sospechosos pero posiblemente legítimos |
| 36 – 60 | HIGH | Múltiples señales de alerta, investigar antes de instalar |
| 61 – 100 | CRITICAL | Comportamiento altamente sospechoso, no instalar |

### Ejemplos de scores reales

| Paquete | Score | Nivel | Por qué |
|---------|-------|-------|---------|
| `requests` | ~22 | MODERATE | Muchas llamadas de red, pero legítimas |
| `paramiko` | ~38 | HIGH | SSH: network + subprocess, muchas operaciones de red |
| `boto3` | ~20 | MODERATE | Muchos env_access pero son credenciales AWS esperadas |
| Paquete con `exec(b64decode)` + setup hook + subprocess | 80+ | CRITICAL | Combo de ofuscación + ejecución + hook |

---

## Caché en disco

pkgxray mantiene un caché persistente de resultados de escaneo para evitar re-analizar el mismo archivo múltiples veces.

**Ubicación:**
- Linux/macOS: `~/.cache/pkgxray/` (respeta `$XDG_CACHE_HOME`)
- Windows: `%LOCALAPPDATA%\pkgxray\cache\`

**Cómo funciona:**
- La clave del caché es el **SHA-256** del archivo descargado (no el nombre ni la versión)
- Los resultados se almacenan como JSON, un archivo por paquete
- Los archivos se crean con permisos `0o600` (solo lectura del propietario)

**Evicción LRU automática:**
- Cuando el caché supera **200 entradas**, se eliminan las **40 más antiguas** (por tiempo de modificación) antes de escribir la nueva entrada
- Mantiene el uso de disco acotado sin necesidad de un daemon externo

**Robustez:**
- Las claves SHA-256 malformadas se rechazan (validación con regex)
- La deserialización es tolerante: si una severidad guardada es desconocida (por cambio de versión), el finding se omite en lugar de crashear
- La corrupción de un archivo de caché resulta en un cache miss, no en un error

```bash
# Eliminar todo el caché
pkgxray clear-cache
```

---

## Soporte para registros privados

pkgxray puede analizar paquetes publicados en registros PyPI privados (Artifactory, Nexus, GitLab Package Registry, etc.):

```bash
# Via CLI
pkgxray scan mi-paquete --index-url https://pypi.miempresa.com/simple/

# Via variable de entorno
export PKGXRAY_INDEX_URL=https://pypi.miempresa.com/simple/
pkgxray scan mi-paquete
```

**Seguridad del registro:** pkgxray valida la URL del registro antes de usarla — solo acepta `http://` y `https://`. URLs con esquemas `file://`, `ftp://` u otros son rechazadas para prevenir ataques SSRF.

---

## Formatos de salida

### Terminal (default)

Reporte con color usando Rich. Incluye encabezado con metadatos, panel de puntaje coloreado por nivel, tabla de hallazgos ordenada por severidad, y nota sobre archivos binarios y omitidos.

El ancho se fija a 200 caracteres para evitar columnas comprimidas en entornos Jupyter/Colab.

### JSON

```bash
pkgxray scan flask --format json
```

```json
{
  "package_name": "flask",
  "version": "3.0.3",
  "scan_date": "2026-05-22T10:30:00Z",
  "risk_score": 8,
  "risk_level": "LOW",
  "files_analyzed": 23,
  "binary_files_found": 0,
  "summary": {"low": 1, "medium": 2, "high": 0, "critical": 0, "total": 3},
  "skipped_files": [],
  "findings": [
    {
      "severity": "medium",
      "analyzer_name": "dynamic_imports",
      "description": "importlib.import_module() con argumento dinámico",
      "filename": "flask/helpers.py",
      "line_number": 42,
      "code_snippet": "module = importlib.import_module(name)"
    }
  ]
}
```

### HTML

Reporte autocontenido con CSS inline, responsive. Todos los campos se escapan con `html.escape()` para prevenir XSS si el nombre del paquete o las descripciones contienen HTML.

```bash
pkgxray scan requests --format html --output report.html
```

---

## Uso en pipelines CI/CD

El flag `--fail-above` permite integrar pkgxray en pipelines de CI para bloquear instalaciones de paquetes con alto riesgo:

```yaml
# GitHub Actions
- name: Analizar dependencia antes de instalar
  run: |
    pip install pkgxray
    pkgxray scan some-library --fail-above 60
    pip install some-library
```

```bash
# Pre-install hook (ejemplo de script de despliegue)
pkgxray scan $PACKAGE --fail-above 50 || { echo "Paquete rechazado por riesgo elevado"; exit 1; }
```

Códigos de salida:
- `0` — escaneo completado, riesgo dentro del umbral (o sin `--fail-above`)
- `1` — riesgo supera `--fail-above`, o error en la descarga/análisis

---

## Docker

pkgxray incluye imágenes Docker listas para usar, ideales para entornos sin Python instalado,
pipelines de CI/CD aislados, o para garantizar reproducibilidad.

### ¿Por qué Docker?

El análisis de paquetes PyPI implica descargar y procesar código de terceros. Ejecutarlo en un
contenedor añade una capa de aislamiento: el proceso de escaneo corre sin acceso al sistema
anfitrión más allá de lo estrictamente necesario.

### Estructura del Dockerfile

El `Dockerfile` usa una construcción multi-stage:

| Stage | Propósito |
|-------|-----------|
| `base` | Imagen base con pkgxray instalado y usuario sin privilegios |
| `test` | Extiende `base` con pytest y archivos de tests |
| `prod` | Imagen mínima de runtime con healthcheck y volumen de caché |

**Mejoras de seguridad en v1.0.0:**
- Usuario sin privilegios (`pkgxray`) — el proceso no corre como root
- `ca-certificates` incluido — verificación TLS al conectarse a PyPI
- `HEALTHCHECK` en la imagen prod — Docker detecta si el contenedor está roto
- `.dockerignore` — evita copiar archivos innecesarios (notebooks, `.git`, `dist/`)

### Uso con Docker Compose

```bash
# Escaneo básico (salida en terminal)
docker compose run scan requests

# Escaneo de cualquier paquete
docker compose run scan boto3

# Salida JSON (útil para parsear con jq)
docker compose run scan-json flask | jq '.risk_score'

# Reporte HTML guardado en ./reports/report.html
mkdir -p reports
docker compose run scan-html paramiko

# Usar en CI/CD: falla si score >= 60
docker compose run scan-ci some-package

# Limpiar caché de disco compartido
docker compose run clear-cache
```

**El caché de disco se comparte entre escaneos** mediante el volumen `pkgxray-cache`.
El segundo escaneo del mismo paquete es casi instantáneo.

### Testing con Docker

```bash
# Tests rápidos (sin red)
docker compose run test

# Tests con reporte de cobertura
docker compose run test-cov

# Tests de integración (requieren red)
docker compose run test-slow

# Pasar argumentos adicionales a pytest
docker compose run test tests/test_analyzers/ -v -k "code_exec"
```

### Build manual

```bash
# Imagen de producción
docker build --target prod -t pkgxray:latest .

# Escanear un paquete
docker run --rm pkgxray:latest scan requests

# Con volumen para persistir caché
docker run --rm -v pkgxray-cache:/home/pkgxray/.cache/pkgxray pkgxray:latest scan requests
```

---

## Evolución del proyecto

pkgxray fue construido iterativamente a través de múltiples versiones, con cada etapa añadiendo profundidad al análisis y correcciones de precisión.

### v0.1.0 — Fundamentos (mayo 2026)

El núcleo inicial: descarga de paquetes PyPI, extracción de código fuente, y los primeros 7 analizadores basados en AST. Scanner, scorer y reporter en versión básica. Suite inicial de tests.

**Analizadores implementados:** `code_exec`, `subprocess`, `network`, `obfuscation`, `filesystem`, `env_access`, `dynamic_imports`

### v0.2.0 — Estabilización y mejoras de UX

- Mejoras al notebook de demostración con más ejemplos de uso
- Corrección de visualización del reporte HTML en entornos Jupyter/Colab
- Ancho de consola Rich fijado a 200 caracteres para evitar columnas comprimidas
- Scorer calibrado con pesos y topes iniciales
- `ConfigFileAnalyzer` añadido: análisis de `pyproject.toml` y `setup.cfg`
- `ScanResult.skipped_files` para rastrear archivos que no pudieron analizarse
- Flag `--fail-above` y `--verbose` en CLI

### v0.3.0 — Auditoría de seguridad completa (mayo 2026)

La versión más significativa antes de 1.0.0. Se realizó una auditoría completa que produjo 23 mejoras distribuidas en 5 fases:

**Fase 1 — Seguridad del propio pkgxray:**
- Corregida vulnerabilidad XSS en el reporte HTML: todos los campos controlados por el usuario pasan por `html.escape()`
- Corregido bypass de path traversal (zip-slip) en el extractor: validación robusta con `os.path.normpath()` que bloquea variantes como `foo/./../../evil.py`

**Fase 2 — Corrección de analizadores:**
- `is_module_level()` ya no toma `ClassDef` como barrera; el cuerpo de clase se ejecuta al importar
- `filesystem.py`: `list.remove()` y `set.remove()` ya no generan falsos positivos
- `dynamic_imports.py`: `some_obj.import_module()` ya no es falso positivo; `__import__("json")` estático bajado a MEDIUM
- `network.py`: detección de cadenas de atributos como `self.session.get(url)`
- Tres analizadores sin escalado por nivel de módulo corregidos
- Scanner: fallos silenciosos reemplazados por `logger.warning()`

**Fase 3 — Recalibración del scorer:**
- Caps por analizador ajustados con datos de paquetes reales
- Combo `env_access + network` requiere CRITICAL de ambos lados (SDKs legítimos como boto3 ya no puntúan HIGH)

**Fase 4 — CLI y observabilidad:**
- `--fail-above` y `--verbose` refinados
- Logging con niveles en scanner

**Fase 5 — Infraestructura:**
- Caché persistente en disco (`_disk_cache.py`) con SHA-256 como clave
- Soporte para registros PyPI privados (`--index-url` / `PKGXRAY_INDEX_URL`)
- `SetupScriptAnalyzer` especializado en `setup.py`
- AST compartido entre analizadores (evita parsear N veces por archivo)
- 50+ tests nuevos; total: 193 pruebas

### v1.0.0 — Release estable (mayo 2026)

Contribuciones del equipo que cerraron brechas de detección importantes y estabilizaron la infraestructura:

**Nuevas capacidades de detección:**
- `ProcessSpawnAnalyzer`: detecta `Process(target=os.system)`, `Thread(target=subprocess.run)` y `executor.submit(os.system)` — técnica de evasión que antes pasaba desapercibida en los analizadores existentes
- `code_exec` mejorado: detecta acceso indirecto a builtins mediante `__builtins__["exec"]()`, `vars()["exec"]()` y `getattr(__builtins__, "exec")()` — técnicas documentadas en malware real de PyPI

**Infraestructura:**
- Caché LRU con evicción automática (200 entradas máximo, evicta las 40 más antiguas cuando se supera el límite)
- Validación SHA-256 con regex antes de leer/escribir entradas de caché
- Deserialización tolerante a severidades desconocidas (compatibilidad entre versiones)
- Nuevos combos de scoring: `process_spawn + env_access` (+15) y `process_spawn + network` (+10)
- Suite de tests ampliada de 193 a **377 pruebas**, sin regresiones

---

## Historial de versiones

### v1.0.0 — 2026-05-21
- Nuevo analizador `ProcessSpawnAnalyzer`
- `code_exec`: detección de acceso indirecto a builtins
- Caché LRU con evicción automática
- Validación SHA-256 y deserialización tolerante en `_disk_cache`
- Nuevos combos de scoring para `process_spawn`
- 377 pruebas (desde 193)

### v0.3.0 — 2026-05-19
- Corrección XSS en reporter HTML
- Corrección path traversal en extractor
- 6 correcciones en analizadores
- Recalibración completa del scorer
- CLI `--fail-above` y `--verbose`
- Caché persistente en disco
- Soporte registros PyPI privados
- `ConfigFileAnalyzer` y `SetupScriptAnalyzer`
- AST compartido entre analizadores

### v0.2.2 — 2026-04-14
- Corrección de visualización en Jupyter/Colab

### v0.2.0 — 2026-04-XX
- `ConfigFileAnalyzer`
- `ScanResult.skipped_files`
- Scorer con calibración inicial

---

## Licencia

MIT © pkgxray contributors
