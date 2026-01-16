# =============================================================================
# Rediver Agent - Full Image with All Security Tools
# =============================================================================
# This image includes:
# - rediver-agent binary
# - semgrep (SAST with dataflow/taint tracking)
# - gitleaks (secret detection)
# - trivy (SCA, container, IaC scanning)
# - git (for repository operations)
#
# Usage:
#   docker build -t rediver-agent:latest -f docker/Dockerfile .
#   docker run --rm -v $(pwd):/scan rediver-agent -tool semgrep -target /scan
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Go binary
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.appVersion=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o /build/rediver-agent \
    ./cmd/rediver-agent

# -----------------------------------------------------------------------------
# Stage 2: Install security tools
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS tools

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep
RUN pip install --no-cache-dir semgrep

# Install gitleaks
ARG GITLEAKS_VERSION=8.28.0
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install trivy
ARG TRIVY_VERSION=0.67.2
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    | tar -xz -C /usr/local/bin trivy

# Verify installations
RUN semgrep --version && gitleaks version && trivy --version

# -----------------------------------------------------------------------------
# Stage 3: Final runtime image
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Labels following OCI spec
LABEL org.opencontainers.image.title="Rediver Agent"
LABEL org.opencontainers.image.description="Security scanning agent with semgrep, gitleaks, and trivy"
LABEL org.opencontainers.image.vendor="Rediver"
LABEL org.opencontainers.image.source="https://github.com/rediverio/rediver-sdk"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r rediver && useradd -r -g rediver -d /home/rediver -m rediver

# Install semgrep directly in runtime (Python-based tool)
RUN pip install --no-cache-dir semgrep && \
    semgrep --version

# Copy gitleaks and trivy binaries
COPY --from=tools /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/

# Copy rediver-agent binary
COPY --from=builder /build/rediver-agent /usr/local/bin/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create directories
RUN mkdir -p /scan /config /cache && \
    chown -R rediver:rediver /scan /config /cache

# Set environment
ENV HOME=/home/rediver
ENV TRIVY_CACHE_DIR=/cache/trivy
ENV SEMGREP_SEND_METRICS=off

# Switch to non-root user
USER rediver
WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD rediver-agent -version || exit 1

# Default entrypoint
ENTRYPOINT ["rediver-agent"]
CMD ["-help"]
