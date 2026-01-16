// Package core provides the core interfaces and base implementations for the Rediver Scanner SDK.
// Tenants can implement these interfaces to create custom scanners, collectors, and agents.
package core

import (
	"context"

	"github.com/rediverio/rediver-sdk/sdk/ris"
)

// =============================================================================
// Scanner Interface - For running security tools
// =============================================================================

// Scanner is the main interface for security scanning tools.
// Implement this interface to create a custom scanner.
type Scanner interface {
	// Name returns the scanner name (e.g., "semgrep", "trivy")
	Name() string

	// Version returns the scanner version
	Version() string

	// Capabilities returns what the scanner can detect
	Capabilities() []string

	// Scan performs a scan on the target and returns raw output
	Scan(ctx context.Context, target string, opts *ScanOptions) (*ScanResult, error)

	// IsInstalled checks if the underlying tool is available
	IsInstalled(ctx context.Context) (bool, string, error)
}

// ScanOptions configures a scan.
type ScanOptions struct {
	// Target configuration
	TargetDir  string            `yaml:"target_dir" json:"target_dir"`
	Include    []string          `yaml:"include" json:"include"`
	Exclude    []string          `yaml:"exclude" json:"exclude"`
	ConfigFile string            `yaml:"config_file" json:"config_file"`
	ExtraArgs  []string          `yaml:"extra_args" json:"extra_args"`
	Env        map[string]string `yaml:"env" json:"env"`

	// Asset information for linking findings
	RepoURL   string `yaml:"repo_url" json:"repo_url"`
	Branch    string `yaml:"branch" json:"branch"`
	CommitSHA string `yaml:"commit_sha" json:"commit_sha"`

	// Output
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// ScanResult holds the raw scan result before conversion.
type ScanResult struct {
	// Scanner info
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version"`

	// Timing
	StartedAt  int64 `json:"started_at"`
	FinishedAt int64 `json:"finished_at"`
	DurationMs int64 `json:"duration_ms"`

	// Output
	ExitCode int    `json:"exit_code"`
	RawOutput []byte `json:"raw_output,omitempty"`
	Stderr    string `json:"stderr,omitempty"`

	// Error (if scan failed)
	Error string `json:"error,omitempty"`
}

// =============================================================================
// Parser Interface - For converting tool output to RIS
// =============================================================================

// Parser converts scanner output to RIS format.
// Implement this interface to support custom output formats.
type Parser interface {
	// Name returns the parser name (e.g., "sarif", "json", "custom-trivy")
	Name() string

	// SupportedFormats returns the output formats this parser can handle
	SupportedFormats() []string

	// Parse converts raw output to RIS report
	Parse(ctx context.Context, data []byte, opts *ParseOptions) (*ris.Report, error)

	// CanParse checks if the parser can handle the given data
	CanParse(data []byte) bool
}

// ParseOptions configures parsing.
type ParseOptions struct {
	// Tool information
	ToolName string `json:"tool_name"`
	ToolType string `json:"tool_type"` // sast, sca, secret, iac, web3

	// Asset information
	AssetType  ris.AssetType `json:"asset_type"`
	AssetValue string        `json:"asset_value"`
	AssetID    string        `json:"asset_id"`

	// Git information
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`

	// Defaults
	DefaultConfidence int `json:"default_confidence"`
}

// =============================================================================
// Collector Interface - For pulling data from external sources
// =============================================================================

// Collector pulls security data from external sources (GitHub, GitLab, etc.).
// Implement this interface to create a custom collector.
type Collector interface {
	// Name returns the collector name
	Name() string

	// Type returns the source type (e.g., "github", "gitlab", "api")
	Type() string

	// Collect pulls data from the external source
	Collect(ctx context.Context, opts *CollectOptions) (*CollectResult, error)

	// TestConnection verifies the connection to the external source
	TestConnection(ctx context.Context) error
}

// CollectOptions configures data collection.
type CollectOptions struct {
	// Source configuration
	SourceURL  string            `yaml:"source_url" json:"source_url"`
	APIKey     string            `yaml:"api_key" json:"api_key"`
	Headers    map[string]string `yaml:"headers" json:"headers"`
	Query      map[string]string `yaml:"query" json:"query"`

	// Filtering
	Since      int64    `yaml:"since" json:"since"` // Unix timestamp
	Repository string   `yaml:"repository" json:"repository"`
	Branches   []string `yaml:"branches" json:"branches"`

	// Pagination
	PageSize int `yaml:"page_size" json:"page_size"`
	MaxPages int `yaml:"max_pages" json:"max_pages"`
}

// CollectResult holds collected data.
type CollectResult struct {
	// Source info
	SourceName string `json:"source_name"`
	SourceType string `json:"source_type"`

	// Collection timing
	CollectedAt int64 `json:"collected_at"`
	DurationMs  int64 `json:"duration_ms"`

	// Results
	Reports     []*ris.Report `json:"reports"`
	TotalItems  int           `json:"total_items"`
	ErrorItems  int           `json:"error_items"`

	// Cursor for pagination
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// =============================================================================
// Agent Interface - For running as a daemon/service
// =============================================================================

// Agent is a long-running service that manages scanners and collectors.
// Implement this interface to create a custom agent.
type Agent interface {
	// Name returns the agent name
	Name() string

	// Start starts the agent
	Start(ctx context.Context) error

	// Stop gracefully stops the agent
	Stop(ctx context.Context) error

	// Status returns the current agent status
	Status() *AgentStatus

	// AddScanner adds a scanner to the agent
	AddScanner(scanner Scanner) error

	// AddCollector adds a collector to the agent
	AddCollector(collector Collector) error

	// RemoveScanner removes a scanner by name
	RemoveScanner(name string) error

	// RemoveCollector removes a collector by name
	RemoveCollector(name string) error
}

// AgentState represents the state of an agent.
type AgentState string

const (
	AgentStateRunning  AgentState = "running"
	AgentStateStopped  AgentState = "stopped"
	AgentStateStopping AgentState = "stopping"
	AgentStateError    AgentState = "error"
)

// AgentStatus represents the agent's current state.
type AgentStatus struct {
	Name        string     `json:"name"`
	Status      AgentState `json:"status"`
	StartedAt   int64      `json:"started_at,omitempty"`
	Uptime      int64      `json:"uptime_seconds,omitempty"`
	Scanners    []string   `json:"scanners"`
	Collectors  []string   `json:"collectors"`
	LastScan    int64      `json:"last_scan,omitempty"`
	LastCollect int64      `json:"last_collect,omitempty"`
	TotalScans  int64      `json:"total_scans"`
	TotalFindings int64    `json:"total_findings"`
	Errors      int64      `json:"errors"`
	Message     string     `json:"message,omitempty"`
}

// =============================================================================
// Pusher Interface - For sending data to Rediver
// =============================================================================

// Pusher sends data to the Rediver API.
type Pusher interface {
	// PushFindings sends findings to Rediver
	PushFindings(ctx context.Context, report *ris.Report) (*PushResult, error)

	// PushAssets sends assets to Rediver
	PushAssets(ctx context.Context, report *ris.Report) (*PushResult, error)

	// SendHeartbeat sends a heartbeat to Rediver
	SendHeartbeat(ctx context.Context, status *AgentStatus) error

	// TestConnection tests the API connection
	TestConnection(ctx context.Context) error
}

// PushResult holds the result of a push operation.
type PushResult struct {
	Success         bool   `json:"success"`
	Message         string `json:"message,omitempty"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
}

// =============================================================================
// Processor Interface - For the complete scan-parse-push pipeline
// =============================================================================

// Processor orchestrates the complete workflow: scan -> parse -> push.
type Processor interface {
	// Process runs a complete scan workflow
	Process(ctx context.Context, scanner Scanner, opts *ProcessOptions) (*ProcessResult, error)

	// ProcessBatch runs multiple scanners in parallel
	ProcessBatch(ctx context.Context, scanners []Scanner, opts *ProcessOptions) ([]*ProcessResult, error)
}

// ProcessOptions configures the processing workflow.
type ProcessOptions struct {
	// Scan options
	ScanOptions *ScanOptions `yaml:"scan" json:"scan"`

	// Parse options
	ParseOptions *ParseOptions `yaml:"parse" json:"parse"`

	// Push options
	Push      bool `yaml:"push" json:"push"`
	SaveLocal bool `yaml:"save_local" json:"save_local"`
	OutputDir string `yaml:"output_dir" json:"output_dir"`

	// Retry
	MaxRetries int `yaml:"max_retries" json:"max_retries"`
	RetryDelay int `yaml:"retry_delay_seconds" json:"retry_delay_seconds"`
}

// ProcessResult holds the result of a complete processing workflow.
type ProcessResult struct {
	// Scanner info
	ScannerName string `json:"scanner_name"`

	// Scan result
	ScanResult *ScanResult `json:"scan_result"`

	// Parsed report
	Report *ris.Report `json:"report,omitempty"`

	// Push result
	PushResult *PushResult `json:"push_result,omitempty"`

	// Local file if saved
	LocalFile string `json:"local_file,omitempty"`

	// Error
	Error string `json:"error,omitempty"`
}
