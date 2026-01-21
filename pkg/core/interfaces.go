// Package core provides the core interfaces and base implementations for the Rediver Scanner SDK.
// Tenants can implement these interfaces to create custom scanners, collectors, and agents.
package core

import (
	"context"
	"net/http"
	"time"

	"github.com/rediverio/sdk/pkg/ris"
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
	ExitCode  int    `json:"exit_code"`
	RawOutput []byte `json:"raw_output,omitempty"`
	Stderr    string `json:"stderr,omitempty"`

	// Error (if scan failed)
	Error string `json:"error,omitempty"`
}

// =============================================================================
// Scanner Types - Classification of security scanners
// =============================================================================

// ScannerType represents the type of security scanner.
type ScannerType string

const (
	ScannerTypeSAST            ScannerType = "sast"             // Static Application Security Testing
	ScannerTypeDependency      ScannerType = "dependency"       // Software Composition Analysis
	ScannerTypeSecretDetection ScannerType = "secret_detection" // Secret/Credential Detection
	ScannerTypeIaC             ScannerType = "iac"              // Infrastructure as Code
	ScannerTypeContainer       ScannerType = "container"        // Container Image Scanning
	ScannerTypeWeb3            ScannerType = "web3"             // Smart Contract Analysis
)

// =============================================================================
// SCA Scanner Interface - For Software Composition Analysis
// =============================================================================

// ScaScanner performs Software Composition Analysis (dependency scanning).
// It generates SBOM and identifies vulnerabilities in dependencies.
type ScaScanner interface {
	// Name returns the scanner name (e.g., "trivy", "snyk")
	Name() string

	// Type returns the scanner type
	Type() ScannerType

	// Scan performs SCA scan and returns results
	Scan(ctx context.Context, target string, opts *ScaScanOptions) (*ScaResult, error)

	// IsInstalled checks if the scanner is available
	IsInstalled(ctx context.Context) (bool, string, error)
}

// ScaScanOptions configures an SCA scan.
type ScaScanOptions struct {
	// Target
	TargetDir string `yaml:"target_dir" json:"target_dir"`

	// Scan configuration
	SkipDBUpdate   bool `yaml:"skip_db_update" json:"skip_db_update"`
	IgnoreUnfixed  bool `yaml:"ignore_unfixed" json:"ignore_unfixed"`
	IncludeDevDeps bool `yaml:"include_dev_deps" json:"include_dev_deps"`

	// Output
	GenerateSBOM bool   `yaml:"generate_sbom" json:"generate_sbom"`
	SBOMFormat   string `yaml:"sbom_format" json:"sbom_format"` // cyclonedx, spdx

	// Verbose
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// ScaResult holds SCA scan results.
type ScaResult struct {
	// Packages discovered
	Packages []Package `json:"packages"`

	// Dependency relationships
	PackageDependencies []PackageDependency `json:"package_dependencies"`

	// Vulnerabilities found
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	// Timing
	DurationMs int64 `json:"duration_ms"`
}

// Package represents a software package.
type Package struct {
	ID       string   `json:"id"`       // Package URL or unique identifier
	Name     string   `json:"name"`     // Package name
	Version  string   `json:"version"`  // Installed version
	Type     string   `json:"type"`     // npm, maven, pip, etc.
	Licenses []string `json:"licenses"` // License identifiers
	PURL     string   `json:"purl"`     // Package URL (purl spec)
}

// PackageDependency represents a dependency relationship.
type PackageDependency struct {
	PackageID    string   `json:"package_id"`   // Parent package
	Dependencies []string `json:"dependencies"` // Child package IDs
}

// Vulnerability represents a security vulnerability in a package.
type Vulnerability struct {
	// Identity
	ID          string `json:"id"`          // CVE ID or advisory ID
	Fingerprint string `json:"fingerprint"` // For deduplication

	// Package info
	PkgID      string `json:"pkg_id"`      // Affected package ID
	PkgName    string `json:"pkg_name"`    // Package name
	PkgVersion string `json:"pkg_version"` // Installed version

	// Vulnerability info
	Name         string `json:"name"`          // Short title
	Description  string `json:"description"`   // Full description
	Severity     string `json:"severity"`      // critical, high, medium, low
	FixedVersion string `json:"fixed_version"` // Version with fix

	// Metadata
	Metadata *VulnerabilityMetadata `json:"metadata,omitempty"`
}

// VulnerabilityMetadata contains additional vulnerability details.
type VulnerabilityMetadata struct {
	CWEs       []string `json:"cwes,omitempty"`        // CWE identifiers
	References []string `json:"references,omitempty"`  // Advisory URLs
	CVSSScore  float64  `json:"cvss_score,omitempty"`  // CVSS score
	CVSSVector string   `json:"cvss_vector,omitempty"` // CVSS vector string
	Source     string   `json:"source,omitempty"`      // NVD, GHSA, etc.
}

// =============================================================================
// Secret Scanner Interface - For Secret Detection
// =============================================================================

// SecretScanner detects secrets and credentials in code.
type SecretScanner interface {
	// Name returns the scanner name (e.g., "gitleaks", "trufflehog")
	Name() string

	// Type returns the scanner type
	Type() ScannerType

	// Scan performs secret detection and returns results
	Scan(ctx context.Context, target string, opts *SecretScanOptions) (*SecretResult, error)

	// IsInstalled checks if the scanner is available
	IsInstalled(ctx context.Context) (bool, string, error)
}

// SecretScanOptions configures a secret scan.
type SecretScanOptions struct {
	// Target
	TargetDir string `yaml:"target_dir" json:"target_dir"`

	// Scan configuration
	ConfigFile string   `yaml:"config_file" json:"config_file"` // Custom rules file
	Exclude    []string `yaml:"exclude" json:"exclude"`         // Paths to exclude
	NoGit      bool     `yaml:"no_git" json:"no_git"`           // Don't use git history

	// Verification
	Verify bool `yaml:"verify" json:"verify"` // Verify secrets are valid

	// Verbose
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// SecretResult holds secret scan results.
type SecretResult struct {
	// Secrets found
	Secrets []SecretFinding `json:"secrets"`

	// Timing
	DurationMs int64 `json:"duration_ms"`
}

// SecretFinding represents a detected secret.
type SecretFinding struct {
	// Identity
	RuleID      string `json:"rule_id"`     // Detection rule ID
	Fingerprint string `json:"fingerprint"` // For deduplication

	// Classification
	SecretType string `json:"secret_type"` // api_key, password, token, etc.
	Service    string `json:"service"`     // AWS, GitHub, Stripe, etc.

	// Location
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`

	// Content
	Match       string `json:"match"`        // Full matched line
	MaskedValue string `json:"masked_value"` // Redacted secret

	// Metadata
	Entropy float64 `json:"entropy,omitempty"` // Entropy score
	Valid   *bool   `json:"valid,omitempty"`   // If verified
	Author  string  `json:"author,omitempty"`  // Git author
	Commit  string  `json:"commit,omitempty"`  // Git commit
	Date    string  `json:"date,omitempty"`    // Commit date
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
	SourceURL string            `yaml:"source_url" json:"source_url"`
	APIKey    string            `yaml:"api_key" json:"api_key"`
	Headers   map[string]string `yaml:"headers" json:"headers"`
	Query     map[string]string `yaml:"query" json:"query"`

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
	Reports    []*ris.Report `json:"reports"`
	TotalItems int           `json:"total_items"`
	ErrorItems int           `json:"error_items"`

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
	Name          string     `json:"name"`
	Status        AgentState `json:"status"`
	StartedAt     int64      `json:"started_at,omitempty"`
	Uptime        int64      `json:"uptime_seconds,omitempty"`
	Scanners      []string   `json:"scanners"`
	Collectors    []string   `json:"collectors"`
	LastScan      int64      `json:"last_scan,omitempty"`
	LastCollect   int64      `json:"last_collect,omitempty"`
	TotalScans    int64      `json:"total_scans"`
	TotalFindings int64      `json:"total_findings"`
	Errors        int64      `json:"errors"`
	Message       string     `json:"message,omitempty"`

	// System Metrics (collected from agent)
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float64 `json:"memory_percent,omitempty"`
	ActiveJobs    int     `json:"active_jobs,omitempty"`
	Region        string  `json:"region,omitempty"`
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
	Push      bool   `yaml:"push" json:"push"`
	SaveLocal bool   `yaml:"save_local" json:"save_local"`
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

// =============================================================================
// Connector Interface - For managing connections to external systems
// =============================================================================

// Connector manages connection to an external system with authentication,
// rate limiting, and connection pooling.
type Connector interface {
	// Name returns the connector name (e.g., "github", "gitlab")
	Name() string

	// Type returns the connector type (e.g., "scm", "cloud", "ticketing")
	Type() string

	// Connect establishes connection to the external system
	Connect(ctx context.Context) error

	// Close closes the connection
	Close() error

	// IsConnected returns true if connected
	IsConnected() bool

	// TestConnection verifies the connection is working
	TestConnection(ctx context.Context) error

	// HTTPClient returns the configured HTTP client (with auth headers)
	HTTPClient() *http.Client

	// RateLimited returns true if rate limiting is enabled
	RateLimited() bool

	// WaitForRateLimit blocks until rate limit allows next request
	WaitForRateLimit(ctx context.Context) error
}

// ConnectorConfig holds common configuration for connectors.
type ConnectorConfig struct {
	// Authentication
	APIKey      string       `yaml:"api_key" json:"api_key"`
	Token       string       `yaml:"token" json:"token"`
	Username    string       `yaml:"username" json:"username"`
	Password    string       `yaml:"password" json:"password"`
	OAuthConfig *OAuthConfig `yaml:"oauth" json:"oauth,omitempty"`

	// Connection
	BaseURL string        `yaml:"base_url" json:"base_url"`
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Rate limiting
	RateLimit  int `yaml:"rate_limit" json:"rate_limit"`   // requests per hour
	BurstLimit int `yaml:"burst_limit" json:"burst_limit"` // burst size

	// Retry
	MaxRetries int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`

	// Debug
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// OAuthConfig holds OAuth configuration.
type OAuthConfig struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	TokenURL     string   `yaml:"token_url" json:"token_url"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
}

// =============================================================================
// Provider Interface - Complete integration bundles
// =============================================================================

// Provider bundles a Connector with multiple Collectors for complete integration.
type Provider interface {
	// Name returns the provider name (e.g., "github", "aws")
	Name() string

	// Connector returns the underlying connector
	Connector() Connector

	// ListCollectors returns all available collectors
	ListCollectors() []Collector

	// GetCollector returns a specific collector by name
	GetCollector(name string) (Collector, error)

	// Initialize sets up the provider with configuration
	Initialize(ctx context.Context, config *ProviderConfig) error

	// TestConnection tests the provider connection
	TestConnection(ctx context.Context) error

	// Close closes the provider and all collectors
	Close() error
}

// ProviderConfig holds provider configuration.
type ProviderConfig struct {
	// Connector config
	Connector ConnectorConfig `yaml:"connector" json:"connector"`

	// Provider-specific settings
	Settings map[string]any `yaml:"settings" json:"settings"`

	// Which collectors to enable (empty = all)
	EnabledCollectors []string `yaml:"enabled_collectors" json:"enabled_collectors"`
}

// =============================================================================
// Adapter Interface - Format translation
// =============================================================================

// Adapter translates between different data formats and RIS.
type Adapter interface {
	// Name returns the adapter name (e.g., "sarif", "cyclonedx")
	Name() string

	// InputFormats returns supported input formats
	InputFormats() []string

	// OutputFormat returns the output format (usually "ris")
	OutputFormat() string

	// CanConvert checks if the input can be converted
	CanConvert(input []byte) bool

	// Convert transforms input to RIS Report
	Convert(ctx context.Context, input []byte, opts *AdapterOptions) (*ris.Report, error)
}

// AdapterOptions configures adapter behavior.
type AdapterOptions struct {
	// Source information
	SourceName string `yaml:"source_name" json:"source_name"`
	SourceType string `yaml:"source_type" json:"source_type"`

	// Target repository/asset info
	Repository string `yaml:"repository" json:"repository"`
	Branch     string `yaml:"branch" json:"branch"`
	CommitSHA  string `yaml:"commit_sha" json:"commit_sha"`

	// Filtering
	MinSeverity string `yaml:"min_severity" json:"min_severity"`

	// Debug
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// =============================================================================
// Enricher Interface - Threat intelligence enrichment
// =============================================================================

// Enricher adds threat intelligence data to findings.
type Enricher interface {
	// Name returns the enricher name (e.g., "epss", "kev", "nvd")
	Name() string

	// Enrich adds threat intel to a single finding
	Enrich(ctx context.Context, finding *ris.Finding) (*ris.Finding, error)

	// EnrichBatch adds threat intel to multiple findings
	EnrichBatch(ctx context.Context, findings []ris.Finding) ([]ris.Finding, error)
}

// EnricherConfig holds enricher configuration.
type EnricherConfig struct {
	// API endpoint (optional, for custom sources)
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Cache duration
	CacheTTL time.Duration `yaml:"cache_ttl" json:"cache_ttl"`

	// Rate limiting
	RateLimit int `yaml:"rate_limit" json:"rate_limit"`

	// Debug
	Verbose bool `yaml:"verbose" json:"verbose"`
}
