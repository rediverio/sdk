# =============================================================================
# Rediver SDK Makefile
# =============================================================================

.PHONY: all build test lint clean docker docker-slim docker-ci docker-push help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REGISTRY ?= ghcr.io/rediverio
IMAGE_NAME ?= rediver-agent
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

# Default target
all: lint test build

# =============================================================================
# Build
# =============================================================================

build: ## Build the rediver-agent binary
	@echo "Building rediver-agent..."
	@mkdir -p bin
	go build -ldflags="-w -s -X main.appVersion=$(VERSION)" -o bin/rediver-agent ./cmd/rediver-agent
	@echo "Built: bin/rediver-agent"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bin/rediver-agent-linux-amd64 ./cmd/rediver-agent
	GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o bin/rediver-agent-linux-arm64 ./cmd/rediver-agent
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o bin/rediver-agent-darwin-amd64 ./cmd/rediver-agent
	GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o bin/rediver-agent-darwin-arm64 ./cmd/rediver-agent
	GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o bin/rediver-agent-windows-amd64.exe ./cmd/rediver-agent
	@echo "Built binaries in bin/"

install: build ## Install to /usr/local/bin
	@echo "Installing rediver-agent..."
	sudo cp bin/rediver-agent /usr/local/bin/
	@echo "Installed to /usr/local/bin/rediver-agent"

# =============================================================================
# Test
# =============================================================================

test: ## Run tests
	go test -v -race ./...

test-coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# =============================================================================
# Lint
# =============================================================================

lint: ## Run linters
	@echo "Running golangci-lint..."
	@golangci-lint run --config .golangci.yml ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w $(GO_FILES)

# =============================================================================
# Security & Pre-commit
# =============================================================================

pre-commit-install: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	@pip install pre-commit --quiet || pip3 install pre-commit --quiet
	@pre-commit install
	@echo "Pre-commit hooks installed!"

pre-commit-run: ## Run all pre-commit hooks
	@pre-commit run --all-files

security-scan: ## Run full security scan
	@echo "Running full security scan..."
	@echo ""
	@echo "=== Gitleaks (Secret Detection) ==="
	@gitleaks detect --config .gitleaks.toml --source . --verbose || true
	@echo ""
	@echo "=== Golangci-lint with Gosec (Code Security) ==="
	@golangci-lint run --config .golangci.yml ./... || true
	@echo ""
	@echo "=== Trivy (Vulnerability Scan) ==="
	@trivy fs --severity HIGH,CRITICAL --scanners vuln,secret,misconfig . || true
	@echo ""
	@echo "Security scan complete!"

# =============================================================================
# Docker
# =============================================================================

docker: ## Build full Docker image
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):latest -f docker/Dockerfile .

docker-slim: ## Build slim Docker image
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-slim -t $(REGISTRY)/$(IMAGE_NAME):slim -f docker/Dockerfile.slim .

docker-ci: ## Build CI Docker image
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-ci -t $(REGISTRY)/$(IMAGE_NAME):ci -f docker/Dockerfile.ci .

docker-all: docker docker-slim docker-ci ## Build all Docker images

docker-push: ## Push all Docker images
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
	docker push $(REGISTRY)/$(IMAGE_NAME):latest
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-slim
	docker push $(REGISTRY)/$(IMAGE_NAME):slim
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-ci
	docker push $(REGISTRY)/$(IMAGE_NAME):ci

# =============================================================================
# Docker Compose
# =============================================================================

compose-build: ## Build images with docker-compose
	docker compose -f docker/docker-compose.yml build

compose-scan: ## Run scan with docker-compose
	docker compose -f docker/docker-compose.yml run --rm scan

compose-agent: ## Start daemon agent with docker-compose
	docker compose -f docker/docker-compose.yml up -d agent

compose-down: ## Stop all docker-compose services
	docker compose -f docker/docker-compose.yml down

# =============================================================================
# Development
# =============================================================================

dev-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

check-tools: ## Check if scanner tools are installed
	go run ./cmd/rediver-agent -check-tools

run: build ## Run the agent (example)
	./bin/rediver-agent -tools semgrep,gitleaks,trivy -target . -verbose

# =============================================================================
# Clean
# =============================================================================

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean -cache

# =============================================================================
# Help
# =============================================================================

help: ## Show this help
	@echo "Rediver SDK - Make targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build the agent"
	@echo "  make docker         # Build Docker image"
	@echo "  make compose-scan   # Run scan with Docker"
	@echo "  make test           # Run tests"
