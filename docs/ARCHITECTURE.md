# Rediver Architecture Guide

This document explains the core architecture of the Rediver platform and how the SDK components interact with the backend.

## Overview

Rediver is a security platform that collects, analyzes, and manages security findings from various sources. The architecture follows a **Worker-Agent-Component** model.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            REDIVER PLATFORM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         BACKEND API                                  │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │   │
│  │   │   Workers   │    │  Findings   │    │   Assets    │            │   │
│  │   │  Registry   │    │   Storage   │    │  Inventory  │            │   │
│  │   └─────────────┘    └─────────────┘    └─────────────┘            │   │
│  │         ▲                   ▲                  ▲                    │   │
│  │         │                   │                  │                    │   │
│  │         └───────────────────┴──────────────────┘                    │   │
│  │                            │                                         │   │
│  │                     HTTP/REST or gRPC                               │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                │                                            │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
     ┌──────────────▼──────────────┐  ┌──────▼───────────────────┐
     │        AGENT (Local)        │  │      CI/CD Pipeline      │
     │                             │  │                          │
     │  ┌────────────────────────┐ │  │  ┌────────────────────┐  │
     │  │    SDK CLIENT          │ │  │  │    SDK CLIENT      │  │
     │  │  (worker_id: xxx)      │ │  │  │  (worker_id: yyy)  │  │
     │  └────────────────────────┘ │  │  └────────────────────┘  │
     │            │                │  │           │              │
     │  ┌─────────┴─────────┐     │  │  ┌────────┴────────┐     │
     │  │                   │     │  │  │                 │     │
     │  ▼                   ▼     │  │  ▼                 ▼     │
     │ Scanners         Providers │  │ Scanners      Adapters   │
     │ (Semgrep,        (GitHub,  │  │ (Trivy,       (SARIF)    │
     │  Trivy)          AWS)      │  │  Gitleaks)               │
     └────────────────────────────┘  └───────────────────────────┘
```

## Key Concepts

### 1. Worker

A **Worker** is the identity registered on the server. Every component that pushes data to Rediver does so through a Worker.

```go
// Worker is identified by worker_id
client := client.New(&client.Config{
    BaseURL:  "https://api.rediver.io",
    APIKey:   "your-api-key",
    WorkerID: "worker-123",  // ← This is the Worker identity
})
```

**Worker responsibilities:**
- Registered in the backend database
- Receives commands from the server
- Sends heartbeats to report status
- All pushed data is tagged with `worker_id` for audit trail

### 2. Agent

An **Agent** is a long-running process that orchestrates Scanners, Collectors, and Providers. It uses the SDK Client (with a Worker ID) to communicate with the server.

```go
// Agent uses SDK Client with worker_id
agent := core.NewBaseAgent(&core.BaseAgentConfig{
    Name:    "my-agent",
    Version: "1.0.0",
}, client)

agent.AddScanner(scanners.Semgrep())
agent.AddScanner(scanners.Trivy())
agent.AddProvider(providers.GitHub())

agent.Start(ctx)
```

**Agent modes:**
- **Daemon**: Long-running, polls for commands
- **One-shot**: Single scan and exit (CI/CD)
- **Server-controlled**: Receives commands via heartbeat stream

### 3. Components

Components are the building blocks that perform actual work:

| Component | Purpose | Example |
|-----------|---------|---------|
| **Scanner** | Run security tools | `SemgrepScanner`, `TrivyScanner` |
| **Parser** | Convert tool output to RIS | `SARIFParser`, `JSONParser` |
| **Connector** | Manage external connections | `GitHubConnector`, `AWSConnector` |
| **Collector** | Pull data from sources | `RepoCollector`, `AlertCollector` |
| **Provider** | Bundle Connector + Collectors | `GitHubProvider`, `AWSProvider` |
| **Adapter** | Format translation | `SARIFAdapter`, `CycloneDXAdapter` |
| **Enricher** | Add threat intel | `EPSSEnricher`, `KEVEnricher` |

## Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Scanner    │────▶│    Parser    │────▶│  RIS Report  │
│  (Semgrep)   │     │  (SARIF)     │     │              │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
┌──────────────┐     ┌──────────────┐             │
│  Collector   │────▶│  RIS Report  │─────────────┤
│  (GitHub)    │     │              │             │
└──────────────┘     └──────────────┘             │
                                                  ▼
                                          ┌──────────────┐
                                          │  Enricher    │
                                          │  (EPSS/KEV)  │
                                          └──────┬───────┘
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │  SDK Client  │
                                          │ (worker_id)  │
                                          └──────┬───────┘
                                                  │
                                      PushFindings() / PushAssets()
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │  Rediver API │
                                          └──────────────┘
```

## RIS (Rediver Ingest Schema)

All components produce **RIS Reports** - a standardized format for security findings and assets:

```go
report := ris.NewReport()
report.Tool = &ris.Tool{Name: "my-scanner", Version: "1.0"}

// Add findings
report.Findings = append(report.Findings, ris.Finding{
    ID:       "finding-001",
    Type:     ris.FindingTypeVulnerability,
    Title:    "SQL Injection",
    Severity: ris.SeverityCritical,
    Location: &ris.FindingLocation{
        Path:      "src/db.go",
        StartLine: 42,
    },
})

// Push to server
client.PushFindings(ctx, report)
```

## Transport Options

The SDK supports two transport layers:

### HTTP/REST (Default)
```go
client := client.New(&client.Config{
    BaseURL: "https://api.rediver.io",
    APIKey:  "xxx",
})
```

### gRPC (High Performance)
```go
grpcTransport := grpc.NewTransport(&grpc.Config{
    Address: "grpc.rediver.io:9090",
    APIKey:  "xxx",
    UseTLS:  true,
})

// Use gRPC for streaming findings
// Bidirectional heartbeat stream for real-time commands
```

## Implementing Custom Components

### Custom Scanner
```go
type MyScanner struct {
    *core.BaseScanner
}

func (s *MyScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
    // Run your scanning logic
    return &core.ScanResult{
        RawOutput: output,
    }, nil
}
```

### Custom Connector
```go
type MyConnector struct {
    *connectors.BaseConnector
}

func NewMyConnector(apiKey string) *MyConnector {
    return &MyConnector{
        BaseConnector: connectors.NewBaseConnector(&connectors.BaseConnectorConfig{
            Name:    "my-service",
            Type:    "api",
            BaseURL: "https://api.myservice.com",
            Config: &core.ConnectorConfig{
                APIKey:    apiKey,
                RateLimit: 1000, // requests per hour
            },
        }),
    }
}
```

### Custom Provider
```go
type MyProvider struct {
    connector  *MyConnector
    collectors map[string]core.Collector
}

func (p *MyProvider) ListCollectors() []core.Collector {
    return []core.Collector{
        NewDataCollector(p.connector),
        NewAlertCollector(p.connector),
    }
}
```

## Best Practices

1. **Always use Worker ID**: Ensure every SDK client has a unique `worker_id` for traceability.

2. **Rate limiting**: Use `BaseConnector` for external APIs to avoid rate limit errors.

3. **Use RIS format**: Always convert outputs to RIS for consistency.

4. **Enrich with threat intel**: Use `client.EnrichFindings()` to add EPSS/KEV data.

5. **Handle errors gracefully**: Enable retry queue for network resilience:
   ```go
   client.New(&client.Config{
       EnableRetryQueue: true,
   })
   ```

6. **Use gRPC for streaming**: For large batches, use gRPC streaming instead of REST.

## See Also

- [SDK README](../README.md) - Quick start guide
- [API Documentation](../../api/docs/API.md) - Backend API reference
- [RIS Schema](../pkg/ris/types.go) - Full RIS type definitions
