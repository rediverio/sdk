# =============================================================================
# Rediver Agent - Full Image with All Security Tools
# =============================================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Copy everything
COPY . .

# Add replace directive to use local packages (avoids module path mismatch)
RUN go mod edit -replace github.com/rediverio/rediver-sdk=./

# Build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.appVersion=${VERSION}" \
    -o /src/rediver-agent \
    ./cmd/rediver-agent

# -----------------------------------------------------------------------------
# Stage 2: Install security tools
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Stage 3: Final runtime image
# -----------------------------------------------------------------------------
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Rediver Agent"
LABEL org.opencontainers.image.description="Security scanning agent"

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
