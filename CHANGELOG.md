# Registro de cambios

Todos los cambios notables de este proyecto se documentan en este archivo.

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
