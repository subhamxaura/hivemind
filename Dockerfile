# syntax=docker/dockerfile:1
FROM python:3.15.0-slim-bookworm AS build

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN "$VIRTUAL_ENV/bin/pip" install --no-cache-dir --no-compile .

FROM python:3.15.0-slim-bookworm AS runtime
ARG VERSION=0.1.0
ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
LABEL org.opencontainers.image.title="HiveMind" \
      org.opencontainers.image.description="Read-only incident analysis and constrained remediation proposals" \
      org.opencontainers.image.source="https://github.com/subhamxaura/hivemind" \
      org.opencontainers.image.version="$VERSION"
RUN groupadd --system --gid 10001 hivemind \
    && useradd --system --uid 10001 --gid hivemind --no-create-home --shell /usr/sbin/nologin hivemind
WORKDIR /app
COPY --from=build --chown=10001:10001 /opt/venv /opt/venv
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).close()"]
CMD ["uvicorn", "hivemind.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--timeout-keep-alive", "5"]
