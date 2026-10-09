# syntax=docker/dockerfile:1.7
#
# Behind a TLS-inspecting corporate proxy? Pass its CA bundle as a build secret:
#   docker build --secret id=ca_bundle,src=/path/to/corp-ca.pem -t attack-logging-coverage .
#   CA_BUNDLE_FILE=/path/to/corp-ca.pem docker compose up --build
# Without the secret the build is unchanged.

# ---- frontend build ----
FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN --mount=type=secret,id=ca_bundle,target=/tmp/ca_bundle.crt \
    NODE_EXTRA_CA_CERTS="$([ -s /tmp/ca_bundle.crt ] && echo /tmp/ca_bundle.crt)" npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- runtime ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    LCM_DATA_DIR=/data LCM_HOST=0.0.0.0 LCM_PORT=8000
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN --mount=type=secret,id=ca_bundle,target=/tmp/ca_bundle.crt \
    if [ -s /tmp/ca_bundle.crt ]; then \
      cp /tmp/ca_bundle.crt /usr/local/share/ca-certificates/extra-ca.crt && update-ca-certificates >/dev/null 2>&1; \
    fi; \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt pip install --no-cache-dir -r backend/requirements.txt
COPY backend/app ./backend/app
COPY --from=frontend /build/dist ./frontend/dist
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"
WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
