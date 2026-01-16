# syntax=docker/dockerfile:1.7
# =============================================================================
# Rediver Agent - Multi-Target, Multi-Arch, Production-Ready Dockerfile
# Targets:
#   - slim: distroless static, smallest (no tools)
#   - full: runtime with semgrep + gitleaks + trivy
#   - ci:   full + pre-downloaded trivy DB (faster CI)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Go binary (shared)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Copy all source code
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# DEBUG: Check files and environment
RUN ls -la && \
    cat go.mod && \
    cat go.work || echo "go.work not found" && \
    go env

# Download dependencies
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-w -s -X main.appVersion=${VERSION}" \
    -o /out/rediver-agent \
    ./cmd/rediver-agent

# -----------------------------------------------------------------------------
# Stage 2: Tools (shared for full & ci) - multi-arch aware
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS tools

ARG TARGETARCH
ARG SEMGREP_VERSION=1.93.0
ARG GITLEAKS_VERSION=8.28.0
ARG TRIVY_VERSION=0.67.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep once here, then reuse by copying to full/ci
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Download arch-correct binaries for gitleaks & trivy
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) GITLEAKS_ARCH="x64";   TRIVY_ARCH="64bit" ;; \
    arm64) GITLEAKS_ARCH="arm64"; TRIVY_ARCH="ARM64" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/gitleaks /usr/local/bin/trivy

# -----------------------------------------------------------------------------
# Stage 3: Tools with pre-downloaded Trivy DB (for CI target)
# -----------------------------------------------------------------------------
FROM tools AS tools-with-db

ENV TRIVY_CACHE_DIR=/root/.cache/trivy
RUN trivy image --download-db-only --no-progress
# (tuỳ nhu cầu) nếu bạn scan Java, bật thêm:
# RUN trivy image --download-java-db-only --no-progress

# -----------------------------------------------------------------------------
# Target: SLIM (distroless, no tools)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS slim

LABEL org.opencontainers.image.title="Rediver Agent Slim"
LABEL org.opencontainers.image.description="Minimal security scanning agent (distroless)"

COPY --from=builder /out/rediver-agent /usr/local/bin/rediver-agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
# Cert bundle from builder (alpine). If you ever change builder base, re-check this path.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/rediver-agent"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: FULL (all tools, non-root)
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS full

LABEL org.opencontainers.image.title="Rediver Agent"
LABEL org.opencontainers.image.description="Security scanning agent with semgrep, gitleaks, trivy"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r rediver && useradd -r -g rediver -d /home/rediver -m rediver

# Reuse semgrep + python packages from tools stage (no reinstall)
COPY --from=tools /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=tools /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/

COPY --from=builder /out/rediver-agent /usr/local/bin/rediver-agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

RUN mkdir -p /scan /config /cache \
    && chown -R rediver:rediver /scan /config /cache

ENV HOME=/home/rediver
ENV TRIVY_CACHE_DIR=/cache/trivy

USER rediver
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/rediver-agent"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: CI (full + trivy DB preloaded + CI-friendly defaults)
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS ci

LABEL org.opencontainers.image.title="Rediver Agent CI"
LABEL org.opencontainers.image.description="CI-optimized security scanning agent (preloaded Trivy DB)"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Copy semgrep + tools + trivy DB cache
COPY --from=tools-with-db /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-with-db /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=tools-with-db /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools-with-db /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-with-db /root/.cache/trivy /root/.cache/trivy

COPY --from=builder /out/rediver-agent /usr/local/bin/rediver-agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV TRIVY_CACHE_DIR=/root/.cache/trivy
ENV TRIVY_NO_PROGRESS=true
ENV CI=true

# Avoid "dubious ownership" in GitHub Actions workspace
RUN git config --global --add safe.directory '*'

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/rediver-agent"]
CMD ["-auto-ci", "-verbose"]