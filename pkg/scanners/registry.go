// Package scanners provides scanner implementations for various security tools.
package scanners

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rediverio/sdk/pkg/core"
	"github.com/rediverio/sdk/pkg/scanners/gitleaks"
	"github.com/rediverio/sdk/pkg/scanners/nuclei"
	"github.com/rediverio/sdk/pkg/scanners/semgrep"
	"github.com/rediverio/sdk/pkg/scanners/trivy"
)

// =============================================================================
// Scanner Registry - Plugin system for scanners
// =============================================================================

// Registry manages registered scanners.
type Registry struct {
	secretScanners map[string]core.SecretScanner
	sastScanners   map[string]core.Scanner
	scaScanners    map[string]core.ScaScanner
	mu             sync.RWMutex
}

// NewRegistry creates a new scanner registry with built-in scanners.
func NewRegistry() *Registry {
	registry := &Registry{
		secretScanners: make(map[string]core.SecretScanner),
		sastScanners:   make(map[string]core.Scanner),
		scaScanners:    make(map[string]core.ScaScanner),
	}

	// Register built-in scanners
	registry.RegisterSecretScanner(gitleaks.NewScanner())
	registry.RegisterSASTScanner(semgrep.NewScanner())
	// Trivy is registered via preset functions, not as ScaScanner
	// because it implements the general Scanner interface

	return registry
}

// RegisterSecretScanner adds a secret scanner to the registry.
func (r *Registry) RegisterSecretScanner(scanner core.SecretScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secretScanners[scanner.Name()] = scanner
}

// GetSecretScanner returns a secret scanner by name.
func (r *Registry) GetSecretScanner(name string) core.SecretScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.secretScanners[name]
}

// ListSecretScanners returns all registered secret scanner names.
func (r *Registry) ListSecretScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.secretScanners))
	for name := range r.secretScanners {
		names = append(names, name)
	}
	return names
}

// RegisterSASTScanner adds a SAST scanner to the registry.
func (r *Registry) RegisterSASTScanner(scanner core.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sastScanners[scanner.Name()] = scanner
}

// GetSASTScanner returns a SAST scanner by name.
func (r *Registry) GetSASTScanner(name string) core.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sastScanners[name]
}

// ListSASTScanners returns all registered SAST scanner names.
func (r *Registry) ListSASTScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.sastScanners))
	for name := range r.sastScanners {
		names = append(names, name)
	}
	return names
}

// RegisterSCAScanner adds an SCA scanner to the registry.
func (r *Registry) RegisterSCAScanner(scanner core.ScaScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scaScanners[scanner.Name()] = scanner
}

// GetSCAScanner returns an SCA scanner by name.
func (r *Registry) GetSCAScanner(name string) core.ScaScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scaScanners[name]
}

// ListSCAScanners returns all registered SCA scanner names.
func (r *Registry) ListSCAScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.scaScanners))
	for name := range r.scaScanners {
		names = append(names, name)
	}
	return names
}

// =============================================================================
// Preset Scanners - Ready-to-use scanner instances
// =============================================================================

// GitleaksScanner is a type alias for external package access.
type GitleaksScanner = gitleaks.Scanner

// Gitleaks returns a new gitleaks scanner with default configuration.
func Gitleaks() *gitleaks.Scanner {
	return gitleaks.NewScanner()
}

// GitleaksWithConfig returns a gitleaks scanner with custom configuration.
func GitleaksWithConfig(opts GitleaksOptions) *gitleaks.Scanner {
	scanner := gitleaks.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.ConfigFile != "" {
		scanner.ConfigFile = opts.ConfigFile
	}
	if opts.OutputFile != "" {
		scanner.OutputFile = opts.OutputFile
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	scanner.Verbose = opts.Verbose
	return scanner
}

// GitleaksOptions configures the gitleaks scanner.
type GitleaksOptions struct {
	Binary     string        // Path to gitleaks binary
	ConfigFile string        // Custom gitleaks config file
	OutputFile string        // Output file path
	Timeout    time.Duration // Scan timeout
	Verbose    bool          // Enable verbose output
}

// Semgrep returns a new semgrep scanner with default configuration.
func Semgrep() *semgrep.Scanner {
	return semgrep.NewScanner()
}

// SemgrepWithConfig returns a semgrep scanner with custom configuration.
func SemgrepWithConfig(opts SemgrepOptions) *semgrep.Scanner {
	scanner := semgrep.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.OutputFile != "" {
		scanner.OutputFile = opts.OutputFile
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if len(opts.Configs) > 0 {
		scanner.Configs = opts.Configs
	}
	if len(opts.Severities) > 0 {
		scanner.Severities = opts.Severities
	}
	if len(opts.ExcludePaths) > 0 {
		scanner.ExcludePaths = opts.ExcludePaths
	}
	if len(opts.IncludePaths) > 0 {
		scanner.IncludePaths = opts.IncludePaths
	}
	scanner.ProEngine = opts.ProEngine
	scanner.DataflowTrace = opts.DataflowTrace
	if opts.MaxMemory > 0 {
		scanner.MaxMemory = opts.MaxMemory
	}
	if opts.Jobs > 0 {
		scanner.Jobs = opts.Jobs
	}
	scanner.NoGitIgnore = opts.NoGitIgnore
	scanner.Verbose = opts.Verbose
	return scanner
}

// SemgrepOptions configures the semgrep scanner.
type SemgrepOptions struct {
	Binary        string        // Path to semgrep binary
	OutputFile    string        // Output file path
	Timeout       time.Duration // Scan timeout
	Verbose       bool          // Enable verbose output
	Configs       []string      // Config files or registries (default: ["auto"])
	Severities    []string      // Filter by severity: ERROR, WARNING, INFO
	ExcludePaths  []string      // Paths to exclude
	IncludePaths  []string      // Paths to include
	ProEngine     bool          // Use Semgrep Pro engine
	DataflowTrace bool          // Enable dataflow traces (default: true)
	MaxMemory     int           // Max memory in MB (0 = no limit)
	Jobs          int           // Number of parallel jobs (0 = auto)
	NoGitIgnore   bool          // Don't respect .gitignore
}

// TrivyScanner is a type alias for external package access.
type TrivyScanner = trivy.Scanner

// Trivy returns a new trivy scanner with default configuration (filesystem mode).
func Trivy() *trivy.Scanner {
	return trivy.NewScanner()
}

// TrivyFS returns a trivy scanner configured for filesystem scanning.
func TrivyFS() *trivy.Scanner {
	return trivy.NewScanner()
}

// TrivyConfig returns a trivy scanner configured for IaC scanning.
func TrivyConfig() *trivy.Scanner {
	return trivy.NewConfigScanner()
}

// TrivyImage returns a trivy scanner configured for container image scanning.
func TrivyImage() *trivy.Scanner {
	return trivy.NewImageScanner()
}

// TrivyFull returns a trivy scanner that scans for all types (vuln, misconfig, secret).
func TrivyFull() *trivy.Scanner {
	return trivy.NewFullScanner()
}

// TrivyWithConfig returns a trivy scanner with custom configuration.
func TrivyWithConfig(opts TrivyOptions) *trivy.Scanner {
	scanner := trivy.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Mode != "" {
		scanner.Mode = trivy.ScanMode(opts.Mode)
	}
	if len(opts.Scanners) > 0 {
		scanner.Scanners = opts.Scanners
	}
	if len(opts.Severity) > 0 {
		scanner.Severity = opts.Severity
	}
	if len(opts.SkipDirs) > 0 {
		scanner.SkipDirs = opts.SkipDirs
	}
	if len(opts.SkipFiles) > 0 {
		scanner.SkipFiles = opts.SkipFiles
	}
	if opts.CacheDir != "" {
		scanner.CacheDir = opts.CacheDir
	}
	scanner.IgnoreUnfixed = opts.IgnoreUnfixed
	scanner.SkipDBUpdate = opts.SkipDBUpdate
	scanner.OfflineScan = opts.OfflineScan
	scanner.Verbose = opts.Verbose
	return scanner
}

// TrivyOptions configures the trivy scanner.
type TrivyOptions struct {
	Binary        string        // Path to trivy binary
	Timeout       time.Duration // Scan timeout
	Mode          string        // Scan mode: fs, config, image, repo
	Scanners      []string      // Scanners: vuln, misconfig, secret, license
	Severity      []string      // Severity filter: CRITICAL, HIGH, MEDIUM, LOW
	SkipDirs      []string      // Directories to skip
	SkipFiles     []string      // Files to skip
	CacheDir      string        // Trivy cache directory
	IgnoreUnfixed bool          // Ignore unfixed vulnerabilities
	SkipDBUpdate  bool          // Skip vulnerability DB update
	OfflineScan   bool          // Run in offline mode
	Verbose       bool          // Enable verbose output
}

// NucleiScanner is a type alias for external package access.
type NucleiScanner = nuclei.Scanner

// Nuclei returns a new nuclei scanner with default configuration.
func Nuclei() *nuclei.Scanner {
	return nuclei.NewScanner()
}

// NucleiDAST returns a nuclei scanner configured for DAST scanning with safe defaults.
func NucleiDAST() *nuclei.Scanner {
	return nuclei.NewDAST()
}

// NucleiVuln returns a nuclei scanner focused on CVE/vulnerability detection.
func NucleiVuln() *nuclei.Scanner {
	return nuclei.NewVulnScanner()
}

// NucleiMisconfig returns a nuclei scanner focused on misconfiguration detection.
func NucleiMisconfig() *nuclei.Scanner {
	return nuclei.NewMisconfigScanner()
}

// NucleiTakeover returns a nuclei scanner focused on subdomain takeover detection.
func NucleiTakeover() *nuclei.Scanner {
	return nuclei.NewTakeoverScanner()
}

// NucleiWithConfig returns a nuclei scanner with custom configuration.
func NucleiWithConfig(opts NucleiOptions) *nuclei.Scanner {
	scanner := nuclei.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if len(opts.Tags) > 0 {
		scanner.Tags = opts.Tags
	}
	if len(opts.ExcludeTags) > 0 {
		scanner.ExcludeTags = opts.ExcludeTags
	}
	if len(opts.Severity) > 0 {
		scanner.Severity = opts.Severity
	}
	if len(opts.Templates) > 0 {
		scanner.Templates = opts.Templates
	}
	if opts.TemplateDir != "" {
		scanner.TemplateDir = opts.TemplateDir
	}
	if opts.RateLimit > 0 {
		scanner.RateLimit = opts.RateLimit
	}
	if opts.Concurrency > 0 {
		scanner.Concurrency = opts.Concurrency
	}
	if opts.Proxy != "" {
		scanner.Proxy = opts.Proxy
	}
	scanner.Headless = opts.Headless
	scanner.NoInteractsh = opts.NoInteractsh
	scanner.FollowRedirects = opts.FollowRedirects
	scanner.Verbose = opts.Verbose
	return scanner
}

// NucleiOptions configures the nuclei scanner.
type NucleiOptions struct {
	Binary          string        // Path to nuclei binary
	Timeout         time.Duration // Scan timeout
	Tags            []string      // Filter templates by tags
	ExcludeTags     []string      // Exclude templates by tags
	Severity        []string      // Filter by severity: critical, high, medium, low, info
	Templates       []string      // Specific templates to use
	TemplateDir     string        // Directory containing templates
	RateLimit       int           // Requests per second
	Concurrency     int           // Number of concurrent templates
	Proxy           string        // HTTP/SOCKS proxy
	Headless        bool          // Enable headless browser
	NoInteractsh    bool          // Disable interactsh server
	FollowRedirects bool          // Follow redirects
	Verbose         bool          // Enable verbose output
}

// =============================================================================
// Scanner Utility Functions
// =============================================================================

// CheckInstalled checks if a scanner is installed and returns version info.
func CheckInstalled(ctx context.Context, scanner interface {
	IsInstalled(context.Context) (bool, string, error)
}) (bool, string, error) {
	return scanner.IsInstalled(ctx)
}

// MustBeInstalled checks if a scanner is installed and panics if not.
func MustBeInstalled(ctx context.Context, scanner interface {
	IsInstalled(context.Context) (bool, string, error)
	Name() string
}) {
	installed, _, err := scanner.IsInstalled(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to check if %s is installed: %v", scanner.Name(), err))
	}
	if !installed {
		panic(fmt.Sprintf("%s is not installed", scanner.Name()))
	}
}
