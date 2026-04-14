FROM python:3.11-slim

LABEL maintainer="pkgxray contributors"
LABEL description="Analyze PyPI packages for suspicious behavior"

WORKDIR /app

# Copiar archivos de proyecto
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# Instalar el paquete
RUN pip install --no-cache-dir .

# Instalar dependencias de test
RUN pip install --no-cache-dir pytest pytest-cov

# Copiar tests
COPY tests/ tests/

ENTRYPOINT ["pkgxray"]
CMD ["--help"]
