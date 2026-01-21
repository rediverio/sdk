# Rediver SDK

Go SDK for building security scanners, collectors, and agents that integrate with the Rediver platform.

## Installation

```bash
go get github.com/rediverio/sdk@latest
```

For private repositories, configure Go to access GitHub:

```bash
# Set GOPRIVATE to bypass public proxy
export GOPRIVATE=github.com/rediverio/*

# Configure Git authentication (choose one):
# Option A: SSH key (recommended)
git config --global url."git@github.com:".insteadOf "https://github.com/"

# Option B: GitHub token
git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

## Quick Start

### 1. Create a Custom Scanner

```go
package main

import (
    "context"
    "github.com/rediverio/sdk/pkg/core"
)

// MyScanner implements core.Scanner interface
type MyScanner struct {
    *core.BaseScanner // Embed base for common functionality
}

func NewMyScanner() *MyScanner {
    return &MyScanner{
        BaseScanner: core.NewBaseScanner(&core.BaseScannerConfig{
            Name:         "my-scanner",
            Binary:       "my-tool",
            DefaultArgs:  []string{"scan", "--json", "{target}"},
            Timeout:      30 * time.Minute,
            OKExitCodes:  []int{0, 1},
            Capabilities: []string{"sast", "custom"},
        }),
    }
}

// Override BuildArgs for custom argument handling
func (s *MyScanner) BuildArgs(target string, opts *core.ScanOptions) []string {
    args := s.BaseScanner.BuildArgs(target, opts)
    // Add custom logic
    return args
}
```

### 2. Create a Custom Parser

```go
package main

import (
    "context"
    "encoding/json"
    "github.com/rediverio/sdk/pkg/core"
    "github.com/rediverio/sdk/pkg/ris"
)

type MyParser struct{}

func (p *MyParser) Name() string {
    return "my-parser"
}

func (p *MyParser) SupportedFormats() []string {
    return []string{"json"}
}

func (p *MyParser) CanParse(data []byte) bool {
    // Check if data matches expected format
    var result map[string]interface{}
    return json.Unmarshal(data, &result) == nil
}

func (p *MyParser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ris.Report, error) {
    // Parse data and convert to RIS format
    report := ris.NewReport()
    // ... conversion logic
    return report, nil
}
```

### 3. Create a Custom Collector

```go
package main

import (
    "context"
    "github.com/rediverio/sdk/pkg/core"
)

type MyCollector struct {
    apiKey string
}

func (c *MyCollector) Name() string {
    return "my-collector"
}

func (c *MyCollector) Type() string {
    return "api"
}

func (c *MyCollector) Collect(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error) {
    // Fetch data from external API
    // Convert to RIS reports
    return &core.CollectResult{
        SourceName: c.Name(),
        SourceType: c.Type(),
        Reports:    reports,
    }, nil
}

func (c *MyCollector) TestConnection(ctx context.Context) error {
    // Verify API connectivity
    return nil
}
```

### 4. Use Native Scanners

```go
package main

import (
    "context"
    "github.com/rediverio/sdk/pkg/scanners"
    "github.com/rediverio/sdk/pkg/core"
)

func main() {
    ctx := context.Background()

    // Use pre-built semgrep scanner
    semgrepScanner := scanners.Semgrep()
    semgrepScanner.Verbose = true
    semgrepScanner.DataflowTrace = true // Enable taint tracking

    result, err := semgrepScanner.Scan(ctx, "./src", &core.ScanOptions{})
    if err != nil {
        panic(err)
    }

    // Parse to RIS
    parser := &semgrep.Parser{}
    report, _ := parser.Parse(ctx, result.RawOutput, nil)

    fmt.Printf("Found %d findings\n", len(report.Findings))
}
```

### 5. CI Environment Detection

```go
package main

import (
    "github.com/rediverio/sdk/pkg/gitenv"
    "github.com/rediverio/sdk/pkg/strategy"
)

func main() {
    // Auto-detect CI environment
    ci := gitenv.Detect()

    if ci != nil {
        fmt.Printf("CI: %s\n", ci.Provider())         // "github" or "gitlab"
        fmt.Printf("Repo: %s\n", ci.ProjectName())     // "org/repo"
        fmt.Printf("Branch: %s\n", ci.CommitBranch())  // "feature/xyz"
        fmt.Printf("MR/PR: %s\n", ci.MergeRequestID()) // "123"
    }

    // Determine scan strategy
    scanCtx := &strategy.ScanContext{
        GitEnv:   ci,
        RepoPath: ".",
    }
    scanStrategy, changedFiles := strategy.DetermineStrategy(scanCtx)
    // scanStrategy: AllFiles or ChangedFileOnly
}
```

### 6. Push Results to Rediver

```go
package main

import (
    "context"
    "github.com/rediverio/sdk/pkg/client"
    "github.com/rediverio/sdk/pkg/ris"
)

func main() {
    ctx := context.Background()

    // Create API client
    apiClient := client.New(&client.Config{
        BaseURL:  "https://api.rediver.io",
        APIKey:   "your-api-key",
        AgentID: "agent-123",
    })

    // Push findings
    report := &ris.Report{...}
    result, err := apiClient.PushFindings(ctx, report)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Created: %d, Updated: %d\n",
        result.FindingsCreated, result.FindingsUpdated)
}
```

### 6b. Using Functional Options (AWS SDK style)

```go
package main

import (
    "context"
    "time"
    "github.com/rediverio/sdk/pkg/client"
)

func main() {
    ctx := context.Background()

    // Create client using functional options
    apiClient := client.NewWithOptions(
        client.WithBaseURL("https://api.rediver.io"),
        client.WithAPIKey("your-api-key"),
        client.WithAgentID("agent-123"),
        client.WithTimeout(30 * time.Second),
        client.WithRetry(3, 2*time.Second),
        client.WithVerbose(true),
    )

    // Push findings...
}
```

### 6c. Error Handling Best Practices

```go
package main

import (
    "github.com/rediverio/sdk/pkg/client"
)

func handleError(err error) {
    if client.IsAuthenticationError(err) {
        // 401 - Invalid API key
        log.Fatal("Authentication failed")
    }

    if client.IsAuthorizationError(err) {
        // 403 - No permission
        log.Fatal("Access denied")
    }

    if client.IsRateLimitError(err) {
        // 429 - Rate limited
        log.Println("Rate limited, will retry...")
    }

    if client.IsRetryable(err) {
        // Network errors, 5xx errors (except 501)
        log.Println("Retryable error, will retry...")
    }

    if httpErr, ok := client.IsHTTPError(err); ok {
        log.Printf("HTTP %d: %s", httpErr.StatusCode, httpErr.Body)
    }
}
```

### 6d. Using GitHub Provider

```go
package main

import (
    "context"
    "github.com/rediverio/sdk/pkg/providers/github"
    "github.com/rediverio/sdk/pkg/core"
)

func main() {
    ctx := context.Background()

    // Create GitHub provider
    provider := github.NewProvider(&github.Config{
        Token:        os.Getenv("GITHUB_TOKEN"),
        Organization: "my-org",
        RateLimit:    5000, // requests per hour
    })

    // List available collectors
    for _, collector := range provider.ListCollectors() {
        fmt.Printf("- %s\n", collector.Name())
    }
    // Output: repos, code-scanning, dependabot

    // Collect code scanning alerts
    csCollector, _ := provider.GetCollector("code-scanning")
    result, _ := csCollector.Collect(ctx, &core.CollectOptions{
        Repository: "my-org/my-repo",
    })

    fmt.Printf("Found %d findings\n", result.TotalItems)
}
```


### 7. Persistent Retry Queue (Network Resilience)

The SDK includes a persistent retry queue that ensures scan results are never lost due to temporary network failures. Failed uploads are automatically queued to disk and retried with exponential backoff.

```go
package main

import (
    "context"
    "time"
    "github.com/rediverio/sdk/pkg/client"
    "github.com/rediverio/sdk/pkg/ris"
)

func main() {
    ctx := context.Background()

    // Create API client with retry queue enabled
    apiClient := client.New(&client.Config{
        BaseURL:  "https://api.rediver.io",
        APIKey:   "your-api-key",
        AgentID: "agent-123",

        // Enable persistent retry queue
        EnableRetryQueue: true,
        RetryQueueDir:    "~/.rediver/retry-queue", // Default location
        RetryInterval:    5 * time.Minute,          // Check queue every 5 mins
        RetryMaxAttempts: 10,                       // Max 10 retry attempts
        RetryTTL:         7 * 24 * time.Hour,       // Keep items for 7 days
    })
    defer apiClient.Close()

    // Start background retry worker (for daemon mode)
    if err := apiClient.StartRetryWorker(ctx); err != nil {
        log.Printf("Warning: Could not start retry worker: %v", err)
    }
    defer apiClient.StopRetryWorker(ctx)

    // Push findings - automatically queued on failure
    report := &ris.Report{...}
    result, err := apiClient.PushFindings(ctx, report)
    if err != nil {
        // Error occurred, but data is safely queued for retry
        log.Printf("Push failed (queued for retry): %v", err)
    }

    // Check retry queue stats
    stats, _ := apiClient.GetRetryQueueStats(ctx)
    if stats != nil && stats.TotalItems > 0 {
        log.Printf("Retry queue: %d pending items", stats.PendingItems)
    }
}
```

**Retry Queue Features:**

| Feature | Description |
|---------|-------------|
| File-based persistence | Items stored as JSON files in `~/.rediver/retry-queue` |
| Exponential backoff | 5min → 10min → 20min → ... → max 48h |
| Fingerprint deduplication | Prevents duplicate entries using SHA256 hash |
| Configurable TTL | Items automatically expire after configured time |
| Background worker | Periodically processes queue without blocking scans |
| Graceful shutdown | Queue state preserved across restarts |

**Backoff Schedule (default):**

| Attempt | Wait Time |
|---------|-----------|
| 1 | 5 minutes |
| 2 | 10 minutes |
| 3 | 20 minutes |
| 4 | 40 minutes |
| 5 | ~1.3 hours |
| 6 | ~2.6 hours |
| 7 | ~5.3 hours |
| 8 | ~10.6 hours |
| 9 | ~21 hours |
| 10 | 48 hours (max) |
```

### 8. Shared Fingerprint Package

The SDK provides unified fingerprint generation for deduplication, shared with the backend:

```go
package main

import "github.com/rediverio/sdk/pkg/shared/fingerprint"

func main() {
    // SAST findings
    fp := fingerprint.GenerateSAST("src/main.go", "CWE-89", 42, 44)

    // SCA findings
    fp := fingerprint.GenerateSCA("lodash", "4.17.20", "CVE-2021-23337")

    // Secret findings
    fp := fingerprint.GenerateSecret("config.yaml", "api-key", 10, "sk_live_xxx")

    // Misconfiguration findings
    fp := fingerprint.GenerateMisconfiguration("aws_s3_bucket", "my-bucket", "S3-PUBLIC", "main.tf")

    // Auto-detect type based on available fields
    fp := fingerprint.GenerateAuto(fingerprint.Input{
        FilePath:        "package.json",
        PackageName:     "lodash",
        PackageVersion:  "4.17.20",
        VulnerabilityID: "CVE-2021-23337",
    })
}
```

### 9. Shared Severity Package

Unified severity mapping across different scanner formats:

```go
package main

import "github.com/rediverio/sdk/pkg/shared/severity"

func main() {
    // Parse severity from various formats
    level := severity.FromString("HIGH")      // From Trivy
    level := severity.FromString("ERROR")     // From Semgrep
    level := severity.FromString("CRITICAL")  // Standard

    // Convert CVSS score to severity
    level := severity.FromCVSS(9.8)  // Returns severity.Critical

    // Compare severities
    if severity.Critical.IsHigherThan(severity.High) {
        fmt.Println("Critical is higher")
    }

    // Count by severity
    counts := &severity.CountBySeverity{}
    for _, finding := range findings {
        level := severity.FromString(finding.Severity)
        counts.Increment(level)
    }
    fmt.Printf("Critical: %d, High: %d\n", counts.Critical, counts.High)
}
```

## Package Structure

```
sdk/
├── pkg/                    # Public library code
│   ├── core/               # Core interfaces and base implementations
│   ├── ris/                # RIS (Rediver Ingest Schema) types
│   ├── client/             # Rediver API client (HTTP + functional options)
│   ├── scanners/           # Native scanner implementations
│   │   ├── semgrep/        # Semgrep SAST scanner
│   │   ├── gitleaks/       # Gitleaks secret scanner
│   │   └── trivy/          # Trivy SCA scanner
│   ├── connectors/         # External system connectors (rate-limited)
│   │   ├── base.go         # BaseConnector with rate limiting
│   │   └── github/         # GitHub API connector
│   ├── providers/          # Complete integrations (Connector + Collectors)
│   │   └── github/         # GitHub provider with 3 collectors
│   ├── adapters/           # Format adapters (SARIF → RIS)
│   │   └── sarif/          # SARIF to RIS adapter
│   ├── transport/          # Transport layers
│   │   └── grpc/           # gRPC transport with TLS/auth
│   ├── errors/             # Custom error types
│   ├── options/            # Functional options pattern
│   ├── mocks/              # Mock interfaces for testing
│   ├── retry/              # Persistent retry queue
│   ├── shared/             # Shared packages (fingerprint, severity)
│   ├── gitenv/             # CI environment detection
│   ├── strategy/           # Scan strategy determination
│   └── handler/            # Scan lifecycle handlers
├── proto/                  # Protocol Buffer definitions
│   └── rediver/v1/         # gRPC service definitions
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # Agent/Component architecture
│   └── GRPC.md             # gRPC configuration guide
├── examples/               # Usage examples
└── test/                   # Integration tests
```

## Interfaces Overview

| Interface | Purpose | Key Methods |
|-----------|---------|-------------|
| `Scanner` | Run security tools | `Scan()`, `IsInstalled()` |
| `Parser` | Output conversion | `Parse()` → `*ris.Report` |
| `Collector` | External data fetch | `Collect()`, `TestConnection()` |
| `Connector` | External connections | `Connect()`, `WaitForRateLimit()` |
| `Provider` | Bundles Connector + Collectors | `ListCollectors()`, `GetCollector()` |
| `Adapter` | Format translation | `Convert()`, `CanConvert()` |
| `Enricher` | Threat intel enrichment | `Enrich()` |
| `Agent` | Daemon management | `Start()`, `Stop()`, `Status()` |
| `Pusher` | API communication | `PushFindings()`, `SendHeartbeat()` |
| `RetryQueue` | Persistent queue | `Enqueue()`, `Dequeue()`, `Stats()` |

## RIS Schema

The Rediver Ingest Schema (RIS) is the standard format for all findings:

```go
type Finding struct {
    ID          string          // Unique identifier
    Type        FindingType     // vulnerability, secret, misconfiguration, etc.
    Title       string          // Short description
    Description string          // Full description
    Severity    Severity        // critical, high, medium, low, info
    Confidence  int             // 0-100

    // Location
    Location    *FindingLocation // File, line, column

    // Classification
    RuleID      string          // Detection rule ID
    Category    string          // e.g., "SQL Injection"

    // Details (type-specific)
    Vulnerability *VulnerabilityDetails
    Secret        *SecretDetails

    // Taint tracking
    DataFlow    *DataFlow       // Source → Intermediates → Sink

    // Metadata
    Fingerprint string          // For deduplication
    Status      FindingStatus   // open, resolved, suppressed
    Tags        []string
}
```

## CLI Usage

### Installation

```bash
# From source
go install github.com/rediverio/sdk/cmd/agent@latest

# Or build locally
make build
```

### Commands

```bash
# Check available tools
agent -list-tools

# Check tool installation
agent -check-tools

# Install missing tools interactively
agent -install-tools

# Run scan
agent -tool semgrep -target ./src -verbose

# Run multiple scanners
agent -tools semgrep,gitleaks,trivy -target . -push

# Daemon mode
agent -daemon -config config.yaml
```

### Native Scanners

| Tool | Type | Description |
|------|------|-------------|
| `semgrep` | SAST | Code analysis with dataflow/taint tracking |
| `gitleaks` | Secret | Secret and credential detection |
| `trivy` | SCA | Vulnerability scanning (filesystem) |
| `trivy-config` | IaC | Infrastructure misconfiguration |
| `trivy-image` | Container | Container image scanning |
| `trivy-full` | All | vuln + misconfig + secret |

## Docker

### Images

Images are available on both **GitHub Container Registry** and **Docker Hub**:

| Registry | Image | Description | Size |
|----------|-------|-------------|------|
| GHCR | `ghcr.io/rediverio/agent:latest` | Full image with all tools | ~1GB |
| GHCR | `ghcr.io/rediverio/agent:slim` | Minimal (tools mounted) | ~20MB |
| GHCR | `rediverio/agent:ci` | CI/CD optimized | ~1.2GB |
| Docker Hub | `rediverio/agent:latest` | Full image with all tools | ~1GB |
| Docker Hub | `rediverio/agent:slim` | Minimal (tools mounted) | ~20MB |
| Docker Hub | `rediverio/agent:ci` | CI/CD optimized | ~1.2GB |

### Quick Start

```bash
# Pull from Docker Hub
docker pull rediverio/agent:latest

# Or from GHCR
docker pull ghcr.io/rediverio/agent:latest

# Run scan on current directory
docker run --rm -v $(pwd):/scan rediverio/agent:latest \
    -tools semgrep,gitleaks,trivy -target /scan -verbose

# Run scan and push results to platform
docker run --rm -v $(pwd):/scan \
    -e API_URL=https://api.rediver.io \
    -e API_KEY=your-api-key \
    rediverio/agent:latest \
    -tools semgrep,gitleaks,trivy -target /scan -push -verbose

# Using docker-compose
docker compose -f docker/docker-compose.yml run --rm scan
```

### Build Images

```bash
# Build all images
make docker-all

# Or individually
docker build -t agent:latest -f docker/Dockerfile .
docker build -t agent:slim -f docker/Dockerfile.slim .
docker build -t agent:ci -f docker/Dockerfile.ci .
```

## CI/CD Integration

Ready-to-use examples are available in [`examples/ci-cd/`](./examples/ci-cd/).

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for diff-based scanning

      - name: Run Security Scan
        uses: docker://rediverio/agent:ci
        with:
          args: >-
            -tools semgrep,gitleaks,trivy
            -target .
            -auto-ci
            -comments
            -push
            -verbose
            -sarif
            -sarif-output results.sarif
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          API_URL: ${{ secrets.API_URL }}
          API_KEY: ${{ secrets.API_KEY }}

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

security-scan:
  stage: security
  image: rediverio/agent:ci
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
    API_URL: $API_URL
    API_KEY: $API_KEY
  script:
    - |
      agent \
        -tools semgrep,gitleaks,trivy \
        -target . \
        -auto-ci \
        -comments \
        -push \
        -verbose \
        -sarif \
        -sarif-output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Key Features

| Feature | Flag | Description |
|---------|------|-------------|
| Auto CI detection | `-auto-ci` | Detects GitHub/GitLab environment automatically |
| Inline comments | `-comments` | Posts findings as PR/MR inline comments |
| Push to platform | `-push` | Sends results to Rediver platform |
| SARIF output | `-sarif` | Generates SARIF for security dashboards |
| Diff-based scan | Automatic | Only scans changed files in MR/PR context |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `API_URL` | Yes* | Platform API URL |
| `API_KEY` | Yes* | API key for authentication |
| `AGENT_ID` | No | Agent identifier for tracking |
| `REGION` | No | Deployment region (e.g., `us-east-1`, `ap-southeast-1`) |
| `RETRY_QUEUE` | No | Enable retry queue (`true`/`false`) |
| `RETRY_DIR` | No | Custom retry queue directory |
| `GITHUB_TOKEN` | Auto | GitHub token (for PR comments) |
| `GITLAB_TOKEN` | Auto | GitLab token (for MR comments) |

*Required when using `-push` flag

**Region Auto-Detection:** If `REGION` is not set, the agent will auto-detect from cloud environment variables: `AWS_REGION`, `GOOGLE_CLOUD_REGION`, `AZURE_REGION`.

## Best Practices

1. **Embed Base Types**: Use `BaseScanner`, `BaseAgent` to avoid boilerplate
2. **Implement Interfaces**: Follow the interface contracts for compatibility
3. **Use RIS Format**: Convert all outputs to RIS for consistency
4. **Handle Errors**: Use proper error wrapping and types
5. **Support CI Detection**: Use `gitenv.Detect()` for auto-configuration
6. **Generate Fingerprints**: Use consistent fingerprinting for deduplication

## Development

```bash
# Install dev tools
make dev-tools

# Run tests
make test

# Run linters
make lint

# Build
make build

# Build Docker images
make docker-all
```

## License

MIT License - See LICENSE file for details.
