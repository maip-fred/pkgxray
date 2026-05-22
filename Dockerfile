# ── base: dependencias compartidas ───────────────────────────────────────────
FROM python:3.11-slim AS base

LABEL maintainer="pkgxray contributors"
LABEL description="Analyze PyPI packages for suspicious behavior before installing"
LABEL org.opencontainers.image.source="https://github.com/maip-fred/pkgxray"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

# ca-certificates: necesario para verificar TLS al descargar de PyPI
# También instala curl para el healthcheck de la imagen prod
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

# Usuario sin privilegios — buena práctica de seguridad para imágenes de producción
RUN useradd --no-create-home --shell /bin/false pkgxray
USER pkgxray

# ── test: agrega dependencias de desarrollo y archivos de tests ───────────────
FROM base AS test

# Volvemos a root solo para instalar dev deps
USER root
RUN pip install --no-cache-dir ".[dev]"

COPY tests/ tests/

# Regresamos al usuario sin privilegios
USER pkgxray

ENTRYPOINT ["pytest"]
CMD ["tests/", "-v", "--tb=short", "-m", "not slow"]

# ── prod: imagen mínima de runtime ────────────────────────────────────────────
FROM base AS prod

# Directorio de caché: montar como volumen para persistencia entre contenedores
# El directorio debe existir y ser escribible por el usuario pkgxray
USER root
RUN mkdir -p /home/pkgxray/.cache/pkgxray \
    && chown -R pkgxray:pkgxray /home/pkgxray
USER pkgxray

ENV HOME=/home/pkgxray
ENV XDG_CACHE_HOME=/home/pkgxray/.cache

# Healthcheck: verifica que pkgxray responde correctamente
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=2 \
    CMD pkgxray --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["pkgxray"]
CMD ["--help"]
