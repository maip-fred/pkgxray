# pkgxray — Guión de presentación
**Duración total: 15 minutos | 3 presentadores | ~5 min cada uno**

> **Cómo leer este guión:**  
> Las líneas en *cursiva* son instrucciones de qué mostrar en pantalla.  
> El texto normal es lo que se dice en voz alta.  
> Los tiempos son aproximados — ajusta el ritmo según la clase.

---

## PARTE 1 — Alfredo (~5 minutos)
### Introducción, motivación, CLI y arquitectura

---

### 🎙 Apertura (~1 min)

Buenos días. Nuestro proyecto se llama **pkgxray** — una herramienta de análisis de seguridad para paquetes de Python.

El problema que resuelve es concreto: cada vez que haces `pip install alguna-librería`, confías ciegamente en que ese paquete no tiene código malicioso. El ecosistema de PyPI tiene más de medio millón de paquetes, y en los últimos años ha habido ataques documentados donde paquetes con nombres parecidos a librerías populares — lo que se llama *typosquatting* — incluían código que robaba variables de entorno, ejecutaba comandos del sistema, o descargaba payloads externos durante la instalación.

Las herramientas que existen, como `pip audit`, solo revisan vulnerabilidades conocidas en bases de datos de CVEs. Ninguna analiza el **comportamiento** del paquete antes de instalarlo.

pkgxray llena ese vacío: **descarga el paquete, analiza su código fuente con 10 analizadores especializados basados en AST, y produce un reporte de riesgo de 0 a 100 — sin instalar nada en tu entorno.**

---

### 🎙 Demo: instalación y primer escaneo (~2 min)

*→ Abrir el notebook. Ir a la celda de título (celda 0), mostrar brevemente el índice de las 12 partes.*

Vamos directo al notebook. Como ven, el recorrido está dividido en 12 partes. Vamos a ir siguiendo esta secuencia durante la presentación.

*→ Parte 0: ejecutar celda de instalación (celda 2).*

```
!pip install pkgxray --upgrade --quiet
import pkgxray
print(f"✓ pkgxray {pkgxray.__version__} instalado")
```

Ya tenemos pkgxray v1.0.0 instalado. Es una librería pública — cualquiera puede instalarla con `pip install pkgxray`.

*→ Parte 1: ejecutar las tres celdas de CLI (celdas 5, 6, 7).*

Ahora lo más importante: cómo se usa. El comando principal es `pkgxray scan` seguido del nombre del paquete. Vamos a escanear tres paquetes con perfiles de riesgo muy distintos.

Primero `more-itertools`, una librería de utilidades puras. No hace conexiones de red, no ejecuta comandos del sistema. El resultado debería ser **LOW**.

*→ Ejecutar celda 5. Mostrar resultado.*

Exacto, LOW con score muy bajo. Ahora `requests`, que por su naturaleza hace muchas conexiones HTTP — pero es legítimo.

*→ Ejecutar celda 6. Mostrar resultado.*

MODERATE. Y finalmente `paramiko`, que implementa el protocolo SSH — tiene operaciones de red, subprocess y sistema de archivos por diseño.

*→ Ejecutar celda 7. Mostrar resultado.*

HIGH. Y aquí se ve algo importante: pkgxray no dice que paramiko es malicioso — dice que tiene patrones que merecen atención. El score es una señal de alerta, no un veredicto.

*→ Ir brevemente a celda 8, mostrar la tabla de flags del CLI sin ejecutar.*

El CLI tiene otros flags útiles: `--format json` o `--format html` para exportar reportes, `--fail-above N` para integración en CI/CD, y `--index-url` para registros privados. Los veremos después.

---

### 🎙 Arquitectura (~1.5 min)

*→ Parte 2: ejecutar celda 11 (scan de requests con API Python). Mientras corre, hablar.*

Además del CLI, pkgxray expone una API Python completa. Esta celda hace exactamente lo mismo que el comando anterior pero desde código.

*→ Ejecutar celda 13 (fields de ScanResult).*

Lo que devuelve `scan()` es un objeto `ScanResult` con todos estos campos. Aquí usamos `dataclasses.fields()` para listarlos automáticamente.

*→ Ir a Parte 3 (celda 18): mostrar el diagrama ASCII de arquitectura sin ejecutar nada, solo leerlo en pantalla.*

Internamente pkgxray sigue este pipeline. Primero descarga el paquete de PyPI y verifica su SHA-256. Luego lo extrae validando que no haya path traversal — eso es un ataque conocido en archivos zip donde rutas como `../../evil.py` pueden escribir fuera del directorio destino. Después corre los 10 analizadores sobre el AST. Un detalle de diseño importante: el AST se parsea **una sola vez** y se comparte entre todos los analizadores — no parseamos el mismo archivo 10 veces.

*→ Ejecutar celda 19 (get_all_analyzers).*

Aquí están los 10 analizadores. De esto se va a encargar Leonardo ahora.

*→ [TRANSICIÓN]* Le paso la palabra a Leonardo para que nos explique cómo funcionan los analizadores y el sistema de puntuación.

---
---

## PARTE 2 — Leonardo (~5 minutos)
### Los 10 analizadores y el sistema de puntuación

---

### 🎙 Intro a los analizadores (~0.5 min)

*→ Mostrar celda 21 (definición de analyze_snippet).*

Gracias Alfredo. Como ya vieron, pkgxray tiene 10 analizadores. Para demostrarlos, definimos en el notebook un helper llamado `analyze_snippet` que nos permite pasar un fragmento de código directamente y ver qué detecta cada analizador — exactamente como lo hace el scanner internamente.

*→ Ejecutar celda 21.*

Esta función prepara el AST, el mapa de padres y los aliases de importación una sola vez, y se los pasa a todos los analizadores que le indiquemos. Es la misma lógica que usa el scanner real. Con esto podemos demostrar cada analizador de forma aislada.

---

### 🎙 Demo de analizadores clave (~2.5 min)

No vamos a mostrar los 10 en detalle — nos enfocamos en los más representativos y en los que tienen lógica más interesante.

**`code_exec` — Ejecución dinámica**

*→ Parte 4.1: ejecutar celda 23.*

Este analizador detecta `eval()`, `exec()`, `compile()` y carga de librerías nativas con `ctypes`. Lo interesante es la distinción entre niveles: `exec()` dentro de una función es HIGH, pero `exec()` a nivel de módulo — fuera de cualquier función — es CRITICAL, porque se ejecuta automáticamente cuando alguien hace `import`. 

Y algo nuevo en v1.0.0 que yo implementé: detecta acceso indirecto vía `__builtins__["exec"]()` y `getattr(__builtins__, "exec")()`. Estas son técnicas documentadas en malware real de PyPI para evadir detección naive — antes de esta versión pasaban desapercibidas.

**`obfuscation` — Ofuscación**

*→ Parte 4.2: ejecutar celda 25.*

El patrón `exec(base64.b64decode(...))` es la firma clásica de malware en PyPI. Lo interesante aquí es la calibración: `base64.b64decode()` solo no se reporta — es completamente legítimo para manejar imágenes, certificados TLS o auth HTTP básica. Solo es CRITICAL cuando está directamente dentro de `exec()` o `eval()`.

**`env_access` — Variables de entorno**

*→ Parte 4.5: ejecutar celda 31.*

Este analizador distingue entre variables sensibles y no sensibles. `os.environ["HOME"]` es LOW — es una variable inocua. Pero `os.getenv("AWS_SECRET_ACCESS_KEY")` a nivel de módulo es CRITICAL — significa que el paquete roba tus credenciales de AWS en el momento en que lo importas. Y además resuelve aliases: `import os as operating_system` funciona igual.

**`process_spawn` — El analizador nuevo de v1.0.0**

*→ Parte 4.10: ejecutar celda 41.*

Este lo implementé específicamente para v1.0.0 y cierra una brecha de evasión importante. El analizador de subprocess detecta llamadas directas como `os.system("cmd")`. Pero si un atacante escribe `Process(target=os.system, args=("cmd",))`, no hay ninguna llamada directa — la función peligrosa se pasa como referencia. `process_spawn` detecta exactamente ese patrón en `Process`, `Thread`, `executor.submit` y `executor.map`. También resuelve aliases de importación.

---

### 🎙 Sistema de puntuación (~2 min)

*→ Parte 5: ejecutar celda 43.*

Ahora el corazón del sistema: cómo se convierte una lista de hallazgos en un número de 0 a 100.

El score tiene tres componentes. Primero, **pesos por severidad**: LOW vale 1 punto, MEDIUM 3, HIGH 7 y CRITICAL 15. Segundo, **topes por analizador**: para evitar que una librería legítima como `requests` — que tiene muchas llamadas de red — obtenga un score desproporcionado. El analizador de `network` tiene un tope de 8 puntos sin importar cuántos hallazgos produzca. Tercero, **bonificaciones por combos**: aquí está la inteligencia real del sistema.

*→ Mientras la celda muestra los combos, señalar los más importantes.*

El combo más alto es `env_access + network` con +25 puntos. ¿Por qué? Porque leer una variable de entorno con credenciales **y** hacer una llamada de red en el mismo paquete es el patrón exacto de exfiltración de credenciales. Cada cosa por separado puede ser legítima — juntas son una señal muy fuerte.

*→ Ejecutar celda 44 (demostración del scorer con findings sintéticos).*

Aquí lo demostramos con hallazgos sintéticos. Creamos findings de `env_access`, `network`, `obfuscation` y `code_exec`, y vemos cómo el scorer suma los pesos, aplica los topes y activa los combos para llegar al score final.

Los niveles son: LOW hasta 15, MODERATE de 16 a 35, HIGH de 36 a 60, y CRITICAL de 61 en adelante.

*→ [TRANSICIÓN]* Le paso la palabra a Bernardo, que va a mostrarnos la evolución del proyecto entre versiones y el resto de las funcionalidades.

---
---

## PARTE 3 — Bernardo (~5 minutos)
### Evolución del proyecto, formatos, caché, CI/CD y conclusión

---

### 🎙 Antes y después: evolución del proyecto (~1.5 min)

*→ Parte 6: ir a la celda 47.*

Gracias Leonardo. Una de las cosas más importantes que quiero mostrar es la evolución del proyecto, porque pkgxray no llegó a v1.0.0 de un salto — pasó por varias iteraciones de corrección.

En v0.2.x había un bug importante: el analizador trataba el cuerpo de una clase igual que el cuerpo de una función. Pero en Python, el cuerpo de una clase se ejecuta al importar el módulo — igual que el código a nivel de módulo. Este código aquí debería ser CRITICAL, y en v0.2.x se marcaba como HIGH.

*→ Ejecutar celda 47. Mostrar resultado CRITICAL.*

Corregido en v0.3.0. Otro bug: `list.remove(x)` generaba un falso positivo en el analizador de filesystem, porque ambos usan el nombre `remove`. La corrección fue agregar filtrado de receptor: solo se reporta si el receptor es `os`, `pathlib` o `Path`.

*→ Ejecutar la segunda parte de celda 47. Mostrar 0 hallazgos.*

*→ Ir a celda 49.*

Y en v1.0.0 — que es el release de hoy — se añadieron dos detecciones nuevas. La primera ya la vimos con Leonardo: `ProcessSpawnAnalyzer`. La segunda: acceso indirecto a exec vía `__builtins__`. Aquí pueden ver la comparación directa — el `SubprocessAnalyzer` que existía antes devuelve 0 hallazgos para este código de evasión, y el nuevo `ProcessSpawnAnalyzer` lo detecta correctamente.

*→ Ejecutar celda 49.*

---

### 🎙 Formatos de salida (~1 min)

*→ Parte 7: ejecutar celda 51 (JSON por CLI).*

pkgxray soporta tres formatos de salida. Terminal con colores via Rich, que es el default. JSON para integrarse con otras herramientas — por ejemplo, parsearlo con `jq` en un pipeline de shell.

*→ Ejecutar celda 53 (HTML en notebook).*

Y HTML autocontenido que se puede renderizar directamente en el notebook o abrir en el navegador. Todos los campos están sanitizados con `html.escape()` para prevenir XSS — si el nombre del paquete contiene `<script>`, no se inyecta en el reporte.

---

### 🎙 Caché en disco (~1 min)

*→ Parte 8: ejecutar celda 56.*

pkgxray tiene caché de dos niveles. En memoria para la sesión actual, y en disco persistente entre sesiones. La clave del caché es el SHA-256 del archivo descargado — no el nombre del paquete — así que si el mismo archivo está en dos registros distintos, solo se analiza una vez.

*→ Mostrar los tiempos de primera vs segunda llamada.*

Aquí la diferencia: la primera llamada tarda varios segundos en descargar y analizar. La segunda — que lee del caché — tarda milisegundos. Y esta es la mejora de v1.0.0: evicción LRU automática. Cuando el caché supera 200 entradas, elimina las 40 más antiguas. Esto mantiene el uso de disco acotado sin necesidad de un proceso externo.

---

### 🎙 CI/CD y comparativa final (~1.5 min)

*→ Parte 10: ejecutar celda 61.*

Para CI/CD, el flag `--fail-above` permite bloquear instalaciones riesgosas. Esta celda simula un pipeline que audita 4 dependencias contra un umbral de 50 puntos. En un GitHub Actions real sería exactamente esto: `pkgxray scan $PACKAGE --fail-above 60 && pip install $PACKAGE`.

*→ Parte 11: ejecutar celda 66 y luego celda 67 (gráfica matplotlib).*

Y finalmente la comparativa de paquetes reales. Esto valida que el scorer esté bien calibrado: `more-itertools` y `attrs` son LOW, `flask` y `requests` MODERATE, `paramiko` HIGH. Ninguno llega a CRITICAL porque todos son paquetes legítimos — aunque tengan patrones que merecen atención.

*→ Mostrar la gráfica con barras y umbrales.*

---

### 🎙 Limitaciones conocidas (~0.5 min)

*→ Parte 12: mostrar la tabla sin ejecutar (es solo markdown).*

Siendo honestos sobre lo que pkgxray **no** puede hacer: no analiza binarios `.so` o `.pyd`, no detecta evasión muy sofisticada, y no escanea dependencias transitivas. Un score LOW no garantiza que el paquete sea seguro — solo que no encontramos señales con análisis estático. Para máxima seguridad conviene combinarlo con `pip audit` para CVEs conocidos y revisión manual para paquetes muy críticos.

---

### 🎙 Cierre (~0.5 min)

En resumen: construimos pkgxray como una herramienta de análisis de comportamiento para paquetes PyPI. 

- **v0.1.0**: el núcleo — 7 analizadores, CLI, reporte básico.  
- **v0.2.x**: calibración del scorer, ConfigFileAnalyzer, mejoras de UX.  
- **v0.3.0**: auditoría de seguridad completa — XSS en el reporte, path traversal en el extractor, 6 correcciones en analizadores, caché en disco, soporte de registros privados.  
- **v1.0.0**: `ProcessSpawnAnalyzer`, detección de `__builtins__["exec"]`, LRU eviction — y 377 pruebas automatizadas.

Está publicado en PyPI, tiene Docker, CI/CD, notebook interactivo y documentación completa. Queda abierto a preguntas.

---

## Notas para el equipo

### Distribución de tiempo
| Presentador | Secciones del notebook | Tiempo |
|-------------|------------------------|--------|
| Alfredo | Intro + Partes 0, 1, 2, 3 | ~5 min |
| Leonardo | Partes 4 (analizadores clave) y 5 | ~5 min |
| Bernardo | Partes 6, 7, 8, 10, 11, 12 + cierre | ~5 min |

### Celdas a ejecutar durante la presentación
| Celda | Quién | Qué muestra |
|-------|-------|-------------|
| 2 | Alfredo | `pip install` + versión |
| 5, 6, 7 | Alfredo | CLI: LOW / MODERATE / HIGH |
| 11 | Alfredo | API Python, ScanResult |
| 13 | Alfredo | `fields(ScanResult)` |
| 19 | Alfredo | `get_all_analyzers()` |
| 21 | Leonardo | `analyze_snippet()` helper |
| 23 | Leonardo | code_exec: exec directo + __builtins__ |
| 25 | Leonardo | obfuscation: base64 |
| 31 | Leonardo | env_access: AWS key CRITICAL |
| 41 | Leonardo | process_spawn: evasión |
| 43 | Leonardo | scorer: pesos, caps, combos |
| 44 | Leonardo | scorer sintético |
| 47 | Bernardo | ClassDef bug + list.remove fix |
| 49 | Bernardo | process_spawn vs subprocess |
| 51 | Bernardo | JSON format |
| 53 | Bernardo | HTML en notebook |
| 56 | Bernardo | caché: primera vs segunda llamada |
| 61 | Bernardo | CI/CD umbral |
| 66, 67 | Bernardo | comparativa + gráfica |

### Si queda tiempo extra
- Mostrar celda 9: escanear una versión específica de requests (`--version 2.20.0`)
- Mostrar celda 15: findings ordenados por severidad
- Mostrar celda 64: verbose logging en vivo

### Si el tiempo se acorta
- Saltar la celda 53 (HTML en notebook — tarda en renderizar)
- Saltar la celda 64 (verbose logging)
- En la sección de analizadores, mostrar solo `code_exec`, `env_access` y `process_spawn`
