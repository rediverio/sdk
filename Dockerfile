# =============================================================================
# Rediver Agent - Multi-Target Dockerfile
# =============================================================================
# This Dockerfile supports multiple build targets:
#   - slim: Minimal distroless image (no tools, smallest size)
#   - full: Complete image with all security tools
#   - ci:   CI/CD optimized image with pre-downloaded databases
#
# Usage:
#   docker build --target slim -t rediver-agent:slim -f docker/Dockerfile .
#   docker build --target full -t rediver-agent:full -f docker/Dockerfile .
#   docker build --target ci   -t rediver-agent:ci   -f docker/Dockerfile .
# =============================================================================

# =============================================================================
# Stage 1: Build Go binary (Shared across all targets)
# =============================================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

COPY . .

# Add replace directive to use local packages (avoids module path mismatch)
RUN go mod edit -replace github.com/rediverio/rediver-sdk=./

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.appVersion=${VERSION}" \
    -o /src/rediver-agent \
    ./cmd/rediver-agent

# =============================================================================
# Stage 2: Install security tools (Shared for full & ci)
# =============================================================================
FROM python:3.12-slim AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep

ARG GITLEAKS_VERSION=8.28.0
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

ARG TRIVY_VERSION=0.67.2
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    | tar -xz -C /usr/local/bin trivy

# =============================================================================
# Stage 3: Tools with pre-downloaded database (for CI target)
# =============================================================================
FROM tools AS tools-with-db

RUN trivy image --download-db-only

# =============================================================================
# Target: SLIM - Minimal distroless image (no tools)
# =============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS slim

LABEL org.opencontainers.image.title="Rediver Agent Slim"
LABEL org.opencontainers.image.description="Minimal security scanning agent"

COPY --from=builder /src/rediver-agent /usr/local/bin/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /scan

ENTRYPOINT ["rediver-agent"]
CMD ["-help"]

# =============================================================================
# Target: FULL - Complete image with all security tools
# =============================================================================
FROM python:3.12-slim AS full

LABEL org.opencontainers.image.title="Rediver Agent"
LABEL org.opencontainers.image.description="Security scanning agent with all tools"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r rediver && useradd -r -g rediver -d /home/rediver -m rediver

RUN pip install --no-cache-dir semgrep

COPY --from=tools /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/
COPY --from=builder /src/rediver-agent /usr/local/bin/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

RUN mkdir -p /scan /config /cache && chown -R rediver:rediver /scan /config /cache

ENV HOME=/home/rediver
ENV TRIVY_CACHE_DIR=/cache/trivy

USER rediver
WORKDIR /scan

ENTRYPOINT ["rediver-agent"]
CMD ["-help"]

# =============================================================================
# Target: CI - CI/CD optimized image with pre-downloaded databases
# =============================================================================
FROM python:3.12-slim AS ci

LABEL org.opencontainers.image.title="Rediver Agent CI"
LABEL org.opencontainers.image.description="CI/CD optimized security scanning agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from tools stage
COPY --from=tools-with-db /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-with-db /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=tools-with-db /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools-with-db /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-with-db /root/.cache/trivy /root/.cache/trivy
COPY --from=builder /src/rediver-agent /usr/local/bin/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV TRIVY_CACHE_DIR=/root/.cache/trivy
ENV TRIVY_NO_PROGRESS=true
ENV CI=true

RUN git config --global --add safe.directory '*'

WORKDIR /github/workspace

ENTRYPOINT ["rediver-agent"]
CMD ["-auto-ci", "-verbose"]
