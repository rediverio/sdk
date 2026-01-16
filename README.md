# Rediver SDK

Go SDK for building security scanners, collectors, and agents that integrate with the Rediver platform.

## Quick Start

### 1. Create a Custom Scanner

```go
package main

import (
    "context"
    "github.com/rediverio/rediver-sdk/pkg/core"
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
    "github.com/rediverio/rediver-sdk/pkg/core"
    "github.com/rediverio/rediver-sdk/pkg/ris"
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
    "github.com/rediverio/rediver-sdk/pkg/core"
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
    "github.com/rediverio/rediver-sdk/pkg/scanners"
    "github.com/rediverio/rediver-sdk/pkg/core"
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
    "github.com/rediverio/rediver-sdk/pkg/gitenv"
    "github.com/rediverio/rediver-sdk/pkg/strategy"
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
    "github.com/rediverio/rediver-sdk/pkg/client"
    "github.com/rediverio/rediver-sdk/pkg/ris"
)

func main() {
    ctx := context.Background()

    // Create API client
    apiClient := client.New(&client.Config{
        BaseURL:  "https://api.rediver.io",
        APIKey:   "your-api-key",
        WorkerID: "worker-123",
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

## Package Structure

```
rediver-sdk/
├── cmd/                # CLI applications
│   └── rediver-agent/  # Agent CLI
├── pkg/                # Public library code
│   ├── core/           # Core interfaces and base implementations
│   ├── ris/            # RIS (Rediver Ingest Schema) types
│   ├── scanners/       # Native scanner implementations
│   │   ├── semgrep/    # Semgrep SAST scanner
│   │   ├── gitleaks/   # Gitleaks secret scanner
│   │   └── trivy/      # Trivy SCA scanner
│   ├── client/         # Rediver API client
│   ├── gitenv/         # CI environment detection
│   ├── strategy/       # Scan strategy determination
│   └── handler/        # Scan lifecycle handlers
├── internal/           # Private implementation code
├── scripts/            # Build, lint, test scripts
├── examples/           # Usage examples
└── test/               # Integration tests
```

## Interfaces Overview

| Interface | Purpose | Key Methods |
|-----------|---------|-------------|
| `Scanner` | Run security tools | `Scan()`, `IsInstalled()` |
| `SecretScanner` | Secret detection | `Scan()` → `*SecretResult` |
| `ScaScanner` | Dependency scanning | `Scan()` → `*ScaResult` |
| `Parser` | Output conversion | `Parse()` → `*ris.Report` |
| `Collector` | External data fetch | `Collect()`, `TestConnection()` |
| `Agent` | Daemon management | `Start()`, `Stop()`, `Status()` |
| `Pusher` | API communication | `PushFindings()`, `SendHeartbeat()` |

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
go install github.com/rediverio/rediver-sdk/cmd/rediver-agent@latest

# Or build locally
make build
```

### Commands

```bash
# Check available tools
rediver-agent -list-tools

# Check tool installation
rediver-agent -check-tools

# Install missing tools interactively
rediver-agent -install-tools

# Run scan
rediver-agent -tool semgrep -target ./src -verbose

# Run multiple scanners
rediver-agent -tools semgrep,gitleaks,trivy -target . -push

# Daemon mode
rediver-agent -daemon -config config.yaml
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

| Image | Description | Size |
|-------|-------------|------|
| `ghcr.io/rediverio/rediver-agent:latest` | Full image with all tools | ~500MB |
| `ghcr.io/rediverio/rediver-agent:slim` | Minimal (tools mounted) | ~20MB |
| `ghcr.io/rediverio/rediver-agent:ci` | CI/CD optimized | ~600MB |

### Quick Start

```bash
# Run scan on current directory
docker run --rm -v $(pwd):/scan ghcr.io/rediverio/rediver-agent:latest \
    -tools semgrep,gitleaks,trivy -target /scan -verbose

# Using docker-compose
docker compose -f docker/docker-compose.yml run --rm scan
```

### Build Images

```bash
# Build all images
make docker-all

# Or individually
docker build -t rediver-agent:latest -f docker/Dockerfile .
docker build -t rediver-agent:slim -f docker/Dockerfile.slim .
docker build -t rediver-agent:ci -f docker/Dockerfile.ci .
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: docker://ghcr.io/rediverio/rediver-agent:ci
        with:
          args: -tools semgrep,gitleaks,trivy -target . -auto-ci -verbose
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REDIVER_API_URL: ${{ secrets.REDIVER_API_URL }}
          REDIVER_API_KEY: ${{ secrets.REDIVER_API_KEY }}
```

### GitLab CI

```yaml
security-scan:
  image: ghcr.io/rediverio/rediver-agent:ci
  script:
    - rediver-agent -tools semgrep,gitleaks,trivy -target . -auto-ci -verbose
  variables:
    REDIVER_API_URL: $REDIVER_API_URL
    REDIVER_API_KEY: $REDIVER_API_KEY
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `REDIVER_API_URL` | Rediver platform API URL |
| `REDIVER_API_KEY` | API key for authentication |
| `REDIVER_WORKER_ID` | Worker identifier for tracking |
| `GITHUB_TOKEN` | GitHub token (for PR comments) |
| `GITLAB_TOKEN` | GitLab token (for MR comments) |

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
