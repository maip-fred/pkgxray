# Registro de cambios

Todos los cambios notables de este proyecto se documentan en este archivo.

## [0.3.0] - 2026-05-19

### Seguridad
- **BUG-01** `reporter.py`: corregida vulnerabilidad XSS en el reporte HTML. Todos los campos controlados por el usuario (`description`, `filename`, `code_snippet`, `analyzer_name`, `package_name`, `version`) ahora se pasan por `html.escape()` antes de insertarse en el HTML.
- **BUG-02** `extractor.py`: corregido bypass de path traversal (zip-slip). La comprobación `".." in name` se reemplaza por `os.path.normpath()` + `startswith("..")` + `isabs()`. La variante `foo/./../../evil.py` ya no puede evadir la protección.

### Correcciones de analizadores
- **BUG-03** `base.py`: `is_module_level()` ya no toma `ClassDef` como barrera. El cuerpo de una clase se ejecuta al importar — ahora se escala correctamente a `CRITICAL`.
- **BUG-04** `filesystem.py`: `list.remove(x)` y `set.remove(x)` ya no generan falsos positivos. `remove` y `unlink` solo se flaggean cuando el receptor es `os`, `pathlib` o `Path`.
- **BUG-05** `dynamic_imports.py`: `importlib.import_module()` ahora exige que el receptor sea `importlib`. `some_obj.import_module()` ya no genera falso positivo.
- **BUG-06** `dynamic_imports.py`: `__import__("json")` con argumento estático se clasifica como `MEDIUM` (antes `HIGH`) — es equivalente a `import json`.
- **BUG-11** `filesystem.py`, `env_access.py`, `dynamic_imports.py`: las tres carecían de escalado por nivel de módulo. Llamadas peligrosas a nivel de módulo ahora se elevan a `CRITICAL` (P2-05).
- **BUG-12** `scanner.py`: el `except Exception: continue` silencioso fue reemplazado por `logger.warning()`. Los fallos de analizadores ya son visibles.
- `network.py`: nuevo helper `_extract_receiver_name()` detecta cadenas de atributos. `self.session.get(url)` ahora se detecta correctamente.

### Mejoras de precisión
- `filesystem.py`: `_SENSITIVE_PATHS` expandido con `~/.kube/config` (CRITICAL), `~/.npmrc`, `~/.pypirc`, `~/.azure/`, `~/.gnupg/`, `~/.bash_profile`, `~/.docker/config.json`, `~/.git-credentials`, `~/.config/gcloud/` (HIGH).
- `env_access.py`: `_SENSITIVE_ENV_KEYWORDS` expandido con `AWS_ACCESS_KEY`, `AZURE_`, `GCP_`, `GITHUB_TOKEN`, `STRIPE_KEY`, `SLACK_WEBHOOK`, `TWILIO_SID`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `JWT_SECRET`, `SESSION_SECRET`, `MONGO_URI` y más.

### Nuevas funcionalidades
- **CLI `--fail-above N`**: sale con código 1 si `risk_score >= N`. Diseñado para pipelines CI/CD.
- **CLI `--verbose`**: activa `logging.DEBUG` para ver warnings de analizadores y pasos del pipeline.
- **`ConfigFileAnalyzer`**: `pyproject.toml` y `setup.cfg` ya no se ignoran; se analizan sus dependencias de build, entrypoints y hooks.
- **`ScanResult.skipped_files`**: campo nuevo que lista los archivos que no pudieron analizarse (error de sintaxis, encoding, etc.) con el motivo.

### Infraestructura
- Versión `0.3.0` en `pyproject.toml`, `__init__.py`, `cli.py` (dinámico vía `importlib.metadata`) y `downloader.py` (User-Agent actualizado).
- `ExtractedFile` ahora tiene campo `is_config` explícito; el campo `is_setup` ahora es `True` solo para `setup.py` (no para `setup.cfg`). El scanner usa ambos flags para el routing de analizadores.
- `utils.py` ahora contiene `get_version()`, helper centralizado para leer la versión instalada.
- 50+ tests nuevos cubriendo todos los fixes, regresiones y nuevas features.

## [0.2.2] - 2026-04-14

### Corregido
- Reporte en terminal: columnas de la tabla ya no aparecen cortadas en entornos Jupyter/Colab. Se fija el ancho de la consola Rich a 200 caracteres para evitar que la detección automática de terminal devuelva ~80 y comprima las columnas.

## [0.2.1] - 2026-04-14

### Corregido
- `__version__` en `__init__.py` ahora refleja correctamente la versión del paquete

## [0.2.0] - 2026-04-14

### Mejorado
- Reducción significativa de falsos positivos en `subprocess`: ya no se reportan
  importaciones (`import subprocess`), solo las llamadas reales a `subprocess.run()`,
  `subprocess.Popen()`, etc.
- Reducción de falsos positivos en `network`: se eliminaron los findings por importar
  módulos de red (`requests`, `socket`, `httpx`, etc.); ahora solo se reportan llamadas
  concretas como `urlopen()`, `requests.get()`, `socket.connect()`.
- Reducción de falsos positivos en `filesystem`: se eliminó el finding por `open()` en
  modo escritura, que era demasiado común en paquetes legítimos. Se mantiene la detección
  de llamadas destructivas y rutas sensibles.
- Reducción de falsos positivos en `setup_scripts`: `import os` ya no se reporta como
  HIGH en `setup.py` (es ubicuo en paquetes legítimos). Se eliminaron `run()` y `call()`
  de los patrones globales de setup.py para evitar duplicados con la detección de hooks.
- Reducción de falsos positivos en `obfuscation`: `base64.b64decode()` aislado ya no
  se reporta como MEDIUM (es estándar para auth headers, imágenes, certificados TLS).
  Solo se reporta el patrón `exec(base64.b64decode(...))` como CRITICAL.

### Nuevo
- Detección de ejecución al nivel del módulo: `code_exec`, `network` y `subprocess`
  ahora identifican si una llamada peligrosa está al nivel del módulo (fuera de funciones
  y clases). Estas llamadas se ejecutan automáticamente al importar el paquete — sin
  ninguna acción del usuario — y se elevan automáticamente a CRITICAL.

## [0.1.1] - 2026-04-14

### Corregido
- Falsos positivos masivos en el analizador `network`: `.get()` sobre dicts/configs ya no se marca como llamada HTTP de alto riesgo
- Falsos positivos en `env_access`: variables de entorno no sensibles (HOME, TERM, PATH…) rebajadas de MEDIUM a LOW
- Inflación de scores: añadido tope de 20 puntos por analizador para evitar que un solo patrón repetitivo lleve el score a 100/100
- `urllib.parse` ya no se trata como módulo de red (solo `urllib.request`)

## [0.1.0] - 2025-04-14

### Agregado
- Primera versión de pkgxray
- 8 analizadores de seguridad basados en AST:
  - `code_exec`: Detecta ejecución dinámica de código (eval, exec, compile)
  - `network`: Detecta conexiones de red y solicitudes HTTP
  - `filesystem`: Detecta accesos sospechosos al sistema de archivos
  - `env_access`: Detecta accesos a variables de entorno
  - `subprocess`: Detecta ejecución de comandos del sistema operativo
  - `obfuscation`: Detecta técnicas de ofuscación de código
  - `setup_scripts`: Detecta patrones peligrosos en archivos setup.py
  - `dynamic_imports`: Detecta importaciones dinámicas de módulos
- Descargador de paquetes PyPI (sin instalación)
- Extractor de archivos para formatos .tar.gz y .whl
- Sistema de puntuación de riesgo (escala 0-100)
- Reportes en formato terminal, JSON y HTML
- Interfaz de línea de comandos basada en Click
- Soporte para Docker
