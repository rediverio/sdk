// Rediver Agent - Universal Security Scanner/Collector Agent
//
// This agent supports multiple deployment modes:
//
//  1. ONE-SHOT MODE (CI/CD):
//     rediver-agent -tool semgrep -target ./src -push
//
//  2. DAEMON MODE (Continuous):
//     rediver-agent -daemon -config config.yaml
//
//  3. SERVER-CONTROLLED MODE:
//     rediver-agent -daemon -enable-commands -config config.yaml
//
// For more details, see: docs/architecture/deployment-modes.md
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rediverio/rediver-sdk/pkg/client"
	"github.com/rediverio/rediver-sdk/pkg/core"
	"github.com/rediverio/rediver-sdk/pkg/gitenv"
	"github.com/rediverio/rediver-sdk/pkg/handler"
	"github.com/rediverio/rediver-sdk/pkg/ris"
	"github.com/rediverio/rediver-sdk/pkg/scanners"
	"github.com/rediverio/rediver-sdk/pkg/strategy"
)

const (
	appName    = "rediver-agent"
	appVersion = "1.0.0"
)

// Config represents the agent configuration.
type Config struct {
	// Agent settings
	Agent struct {
		Name              string        `yaml:"name"`
		ScanInterval      time.Duration `yaml:"scan_interval"`
		CollectInterval   time.Duration `yaml:"collect_interval"`
		HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
		Verbose           bool          `yaml:"verbose"`

		// Server control
		EnableCommands      bool          `yaml:"enable_commands"`
		CommandPollInterval time.Duration `yaml:"command_poll_interval"`
	} `yaml:"agent"`

	// Rediver API
	Rediver struct {
		BaseURL  string        `yaml:"base_url"`
		APIKey   string        `yaml:"api_key"`
		WorkerID string        `yaml:"worker_id"` // For tenant tracking
		Timeout  time.Duration `yaml:"timeout"`
	} `yaml:"rediver"`

	// Scanners to run
	Scanners []ScannerConfig `yaml:"scanners"`

	// Collectors to run
	Collectors []CollectorConfig `yaml:"collectors"`

	// Targets
	Targets []string `yaml:"targets"`
}

// ScannerConfig configures a scanner.
type ScannerConfig struct {
	Name    string   `yaml:"name"`   // Preset name or "custom"
	Binary  string   `yaml:"binary"` // Binary path (for custom)
	Args    []string `yaml:"args"`   // Command args (for custom)
	Enabled bool     `yaml:"enabled"`
}

// CollectorConfig configures a collector.
type CollectorConfig struct {
	Name         string        `yaml:"name"`  // e.g., "github", "gitlab"
	Token        string        `yaml:"token"` // API token
	Owner        string        `yaml:"owner"` // Org/user
	Repo         string        `yaml:"repo"`  // Repository (optional - all if empty)
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"` // For daemon mode
}

func main() {
	// CLI flags
	configPath := flag.String("config", "", "Path to config file")
	tool := flag.String("tool", "", "Tool to run (semgrep, trivy-fs, gitleaks, etc.)")
	tools := flag.String("tools", "", "Comma-separated list of tools")
	target := flag.String("target", ".", "Target directory to scan")
	apiURL := flag.String("api-url", "", "Rediver API URL (or REDIVER_API_URL env)")
	apiKey := flag.String("api-key", "", "Rediver API key (or REDIVER_API_KEY env)")
	workerID := flag.String("worker-id", "", "Worker ID for tracking (or REDIVER_WORKER_ID env)")
	push := flag.Bool("push", false, "Push results to Rediver")
	daemon := flag.Bool("daemon", false, "Run in daemon mode")
	enableCommands := flag.Bool("enable-commands", false, "Enable server command polling (daemon mode)")
	standalone := flag.Bool("standalone", false, "Standalone mode - no server communication")
	verbose := flag.Bool("verbose", false, "Verbose output")
	listTools := flag.Bool("list-tools", false, "List available tools")
	showVersion := flag.Bool("version", false, "Show version")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	outputFile := flag.String("output", "", "Output file path (instead of stdout)")
	createComments := flag.Bool("comments", false, "Create PR/MR inline comments for findings")
	autoDetectCI := flag.Bool("auto-ci", true, "Auto-detect CI environment (GitHub Actions, GitLab CI)")
	checkTools := flag.Bool("check-tools", false, "Check if required tools are installed and show installation instructions")
	installTools := flag.Bool("install-tools", false, "Interactively install missing tools (requires sudo for some tools)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("%s version %s\n", appName, appVersion)
		os.Exit(0)
	}

	if *listTools {
		fmt.Println("Available scanners:")
		fmt.Println()
		fmt.Println("  Native scanners (recommended):")
		fmt.Printf("    %-15s - %s\n", "semgrep", "SAST scanner with dataflow/taint tracking")
		fmt.Printf("    %-15s - %s\n", "gitleaks", "Secret detection scanner")
		fmt.Printf("    %-15s - %s\n", "trivy", "SCA vulnerability scanner (filesystem)")
		fmt.Printf("    %-15s - %s\n", "trivy-config", "IaC misconfiguration scanner")
		fmt.Printf("    %-15s - %s\n", "trivy-image", "Container image scanner")
		fmt.Printf("    %-15s - %s\n", "trivy-full", "Full scanner (vuln + misconfig + secret)")
		fmt.Println()
		fmt.Println("  Preset scanners:")
		for _, name := range core.ListPresetScanners() {
			cfg := core.PresetScanners[name]
			fmt.Printf("    %-15s - %s\n", name, strings.Join(cfg.Capabilities, ", "))
		}
		fmt.Println()
		fmt.Println("Usage examples:")
		fmt.Println("  rediver-agent -tool semgrep -target ./src -push")
		fmt.Println("  rediver-agent -tools semgrep,gitleaks,trivy -target . -push")
		fmt.Println("  rediver-agent -daemon -config agent.yaml")
		fmt.Println()
		fmt.Println("Check tool installation:")
		fmt.Println("  rediver-agent -check-tools")
		fmt.Println("  rediver-agent -install-tools")
		os.Exit(0)
	}

	if *checkTools || *installTools {
		checkAndInstallTools(context.Background(), *installTools, *verbose)
		os.Exit(0)
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Load config or use CLI flags
	var cfg Config
	if *configPath != "" {
		if err := loadConfig(*configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Build config from CLI flags
		cfg.Agent.Verbose = *verbose
		cfg.Agent.ScanInterval = 1 * time.Hour
		cfg.Agent.HeartbeatInterval = 1 * time.Minute
		cfg.Agent.EnableCommands = *enableCommands
		cfg.Agent.CommandPollInterval = 30 * time.Second

		// API config from flags or env
		cfg.Rediver.BaseURL = getEnvOrFlag(*apiURL, "REDIVER_API_URL")
		cfg.Rediver.APIKey = getEnvOrFlag(*apiKey, "REDIVER_API_KEY")
		cfg.Rediver.WorkerID = getEnvOrFlag(*workerID, "REDIVER_WORKER_ID")
		cfg.Targets = []string{*target}

		// Parse tools
		if *tool != "" {
			cfg.Scanners = []ScannerConfig{{Name: *tool, Enabled: true}}
		} else if *tools != "" {
			for t := range strings.SplitSeq(*tools, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					cfg.Scanners = append(cfg.Scanners, ScannerConfig{Name: t, Enabled: true})
				}
			}
		}
	}

	// Validate required fields
	if len(cfg.Scanners) == 0 && len(cfg.Collectors) == 0 && !cfg.Agent.EnableCommands {
		fmt.Fprintf(os.Stderr, "Error: No scanners or collectors configured.\n")
		fmt.Fprintf(os.Stderr, "Use -tool, -tools, or -config to specify what to run.\n")
		fmt.Fprintf(os.Stderr, "Use -list-tools to see available scanners.\n")
		os.Exit(1)
	}

	// Create API client (unless standalone)
	var apiClient *client.Client
	var pusher core.Pusher
	if !*standalone && cfg.Rediver.BaseURL != "" && cfg.Rediver.APIKey != "" {
		apiClient = client.New(&client.Config{
			BaseURL:  cfg.Rediver.BaseURL,
			APIKey:   cfg.Rediver.APIKey,
			WorkerID: cfg.Rediver.WorkerID,
			Timeout:  cfg.Rediver.Timeout,
			Verbose:  cfg.Agent.Verbose,
		})
		pusher = apiClient

		// Test connection
		if err := pusher.TestConnection(ctx); err != nil {
			fmt.Printf("Warning: Could not connect to Rediver API: %v\n", err)
		} else if cfg.Agent.Verbose {
			fmt.Println("Connected to Rediver API")
			if cfg.Rediver.WorkerID != "" {
				fmt.Printf("Worker ID: %s\n", cfg.Rediver.WorkerID)
			}
		}
	} else if *push && !*standalone {
		fmt.Fprintf(os.Stderr, "Warning: -push specified but no API credentials provided.\n")
		fmt.Fprintf(os.Stderr, "Use -api-url and -api-key, or set REDIVER_API_URL and REDIVER_API_KEY env vars.\n")
	}

	// Determine mode and run
	if *daemon {
		runDaemon(ctx, &cfg, apiClient, pusher)
	} else {
		runOnce(ctx, &cfg, pusher, *push, *outputJSON, *outputFile, *createComments, *autoDetectCI)
	}
}

func getEnvOrFlag(flagVal, envName string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envName)
}

func loadConfig(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Expand environment variables in config
	expanded := os.ExpandEnv(string(data))

	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	return nil
}

func runOnce(ctx context.Context, cfg *Config, pusher core.Pusher, push, outputJSON bool, outputFile string, createComments, autoDetectCI bool) {
	parsers := core.NewParserRegistry()
	var allReports []*ris.Report

	// Auto-detect CI environment
	var ciEnv gitenv.GitEnv
	if autoDetectCI {
		ciEnv = gitenv.DetectWithVerbose(cfg.Agent.Verbose)
		if ciEnv != nil && cfg.Agent.Verbose {
			fmt.Printf("[CI] Detected: %s\n", ciEnv.Provider())
			if ciEnv.ProjectName() != "" {
				fmt.Printf("[CI] Repository: %s\n", ciEnv.ProjectName())
			}
			if ciEnv.CommitBranch() != "" {
				fmt.Printf("[CI] Branch: %s\n", ciEnv.CommitBranch())
			}
			if ciEnv.MergeRequestID() != "" {
				fmt.Printf("[CI] MR/PR: #%s\n", ciEnv.MergeRequestID())
			}
		}
	}

	// Create scan handler
	var scanHandler handler.ScanHandler
	if push && pusher != nil {
		scanHandler = handler.NewRemoteHandler(&handler.RemoteHandlerConfig{
			Pusher:         pusher,
			Verbose:        cfg.Agent.Verbose,
			CreateComments: createComments,
			MaxComments:    10,
		})
	} else {
		scanHandler = handler.NewConsoleHandler(cfg.Agent.Verbose)
	}

	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		// Get or create scanner
		scanner, err := getScanner(scannerCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		// Check if installed
		installed, version, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			fmt.Fprintf(os.Stderr, "Scanner %s not installed: %v\n", scanner.Name(), err)
			continue
		}

		if cfg.Agent.Verbose {
			fmt.Printf("[%s] Version: %s\n", scanner.Name(), version)
		}

		// Notify handler of scan start
		scanInfo, err := scanHandler.OnStart(ciEnv, scanner.Name(), "sast")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Handler OnStart failed: %v\n", scanner.Name(), err)
		}
		_ = scanInfo // May contain LastCommitSha for baseline

		// Scan each target
		for _, target := range cfg.Targets {
			fmt.Printf("[%s] Scanning %s...\n", scanner.Name(), target)

			// Determine scan strategy based on CI context
			scanCtx := &strategy.ScanContext{
				GitEnv:   ciEnv,
				RepoPath: target,
				Verbose:  cfg.Agent.Verbose,
			}
			scanStrategy, changedFiles := strategy.DetermineStrategy(scanCtx)

			if cfg.Agent.Verbose {
				fmt.Printf("[%s] Strategy: %s\n", scanner.Name(), scanStrategy.String())
				if scanStrategy == strategy.ChangedFileOnly {
					fmt.Printf("[%s] Changed files: %d\n", scanner.Name(), len(changedFiles))
				}
			}

			result, err := scanner.Scan(ctx, target, &core.ScanOptions{
				TargetDir: target,
				Verbose:   cfg.Agent.Verbose,
			})

			if err != nil {
				scanHandler.OnError(err)
				fmt.Fprintf(os.Stderr, "[%s] Scan failed: %v\n", scanner.Name(), err)
				continue
			}

			fmt.Printf("[%s] Completed in %dms\n", scanner.Name(), result.DurationMs)

			// Parse results
			parser := parsers.FindParser(result.RawOutput)
			if parser == nil {
				parser = parsers.Get("sarif")
			}

			if parser == nil {
				fmt.Fprintf(os.Stderr, "[%s] No parser available\n", scanner.Name())
				continue
			}

			// Detect asset - prefer CI environment info over local git
			var assetType ris.AssetType
			var assetValue string
			var branch string

			if ciEnv != nil && ciEnv.ProjectName() != "" {
				assetType = ris.AssetTypeRepository
				assetValue = ciEnv.ProjectName()
				branch = ciEnv.CommitBranch()
			} else {
				assetType, assetValue = detectAsset(target)
				branch = detectGitBranch(target)
			}

			if cfg.Agent.Verbose && assetValue != "" {
				fmt.Printf("[%s] Asset: %s (%s)\n", scanner.Name(), assetValue, assetType)
				if branch != "" {
					fmt.Printf("[%s] Branch: %s\n", scanner.Name(), branch)
				}
			}

			report, err := parser.Parse(ctx, result.RawOutput, &core.ParseOptions{
				ToolName:   scanner.Name(),
				AssetType:  assetType,
				AssetValue: assetValue,
				Branch:     branch,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Parse error: %v\n", scanner.Name(), err)
				continue
			}

			allReports = append(allReports, report)

			// Output summary (unless JSON mode)
			if !outputJSON {
				printSummary(scanner.Name(), report)
			}

			// Handle findings via handler (push + PR comments)
			if len(report.Findings) > 0 {
				err = scanHandler.HandleFindings(handler.HandleFindingsParams{
					Report:       report,
					Strategy:     scanStrategy,
					ChangedFiles: changedFiles,
					GitEnv:       ciEnv,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] HandleFindings failed: %v\n", scanner.Name(), err)
				}
			}
		}

		// Notify handler of scan completion
		scanHandler.OnCompleted()
	}

	// Output JSON if requested
	if outputJSON && len(allReports) > 0 {
		var output interface{}
		if len(allReports) == 1 {
			output = allReports[0]
		} else {
			output = map[string]interface{}{
				"reports": allReports,
				"total_findings": func() int {
					count := 0
					for _, r := range allReports {
						count += len(r.Findings)
					}
					return count
				}(),
			}
		}

		data, _ := json.MarshalIndent(output, "", "  ")

		if outputFile != "" {
			if err := os.WriteFile(outputFile, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Results written to %s\n", outputFile)
		} else {
			fmt.Println(string(data))
		}
	}
}

func runDaemon(ctx context.Context, cfg *Config, apiClient *client.Client, pusher core.Pusher) {
	// Create agent
	agentName := cfg.Agent.Name
	if agentName == "" {
		hostname, _ := os.Hostname()
		agentName = fmt.Sprintf("rediver-agent-%s", hostname)
	}

	agent := core.NewBaseAgent(&core.BaseAgentConfig{
		Name:              agentName,
		Version:           appVersion,
		ScanInterval:      cfg.Agent.ScanInterval,
		CollectInterval:   cfg.Agent.CollectInterval,
		HeartbeatInterval: cfg.Agent.HeartbeatInterval,
		Targets:           cfg.Targets,
		Verbose:           cfg.Agent.Verbose,
	}, pusher)

	// Add scanners
	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		scanner, err := getScanner(scannerCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		// Check if installed
		installed, _, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			fmt.Fprintf(os.Stderr, "Warning: Scanner %s not installed, skipping\n", scannerCfg.Name)
			continue
		}

		if err := agent.AddScanner(scanner); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		fmt.Printf("  Added scanner: %s\n", scanner.Name())
	}

	// Add collectors
	for _, collectorCfg := range cfg.Collectors {
		if !collectorCfg.Enabled {
			continue
		}

		collector, err := getCollector(collectorCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating collector %s: %v\n", collectorCfg.Name, err)
			continue
		}

		if err := agent.AddCollector(collector); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding collector %s: %v\n", collectorCfg.Name, err)
			continue
		}

		fmt.Printf("  Added collector: %s\n", collector.Name())
	}

	// Start command poller if enabled
	var poller *core.CommandPoller
	if cfg.Agent.EnableCommands && apiClient != nil {
		executor := core.NewDefaultCommandExecutor(pusher)

		// Add scanners to executor
		for _, scannerCfg := range cfg.Scanners {
			if !scannerCfg.Enabled {
				continue
			}
			scanner, _ := getScanner(scannerCfg, cfg.Agent.Verbose)
			if scanner != nil {
				executor.AddScanner(scanner)
			}
		}

		// Add collectors to executor
		for _, collectorCfg := range cfg.Collectors {
			if !collectorCfg.Enabled {
				continue
			}
			collector, _ := getCollector(collectorCfg, cfg.Agent.Verbose)
			if collector != nil {
				executor.AddCollector(collector)
			}
		}

		pollInterval := cfg.Agent.CommandPollInterval
		if pollInterval == 0 {
			pollInterval = 30 * time.Second
		}

		poller = core.NewCommandPoller(apiClient, executor, &core.CommandPollerConfig{
			PollInterval:  pollInterval,
			MaxConcurrent: 5,
			AllowedTypes:  []string{"scan", "collect", "health_check"},
			Verbose:       cfg.Agent.Verbose,
		})

		// Start poller in background
		go func() {
			if err := poller.Start(ctx); err != nil && err != context.Canceled {
				fmt.Fprintf(os.Stderr, "Command poller error: %v\n", err)
			}
		}()

		fmt.Printf("  Command polling: enabled (interval: %s)\n", pollInterval)
	}

	// Start agent
	if err := agent.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n%s started\n", agentName)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Mode: %s\n", getMode(cfg))
	fmt.Printf("  Targets: %v\n", cfg.Targets)
	if cfg.Agent.ScanInterval > 0 && len(cfg.Targets) > 0 {
		fmt.Printf("  Scan interval: %s\n", cfg.Agent.ScanInterval)
	}
	fmt.Printf("  Heartbeat: %s\n", cfg.Agent.HeartbeatInterval)
	if cfg.Rediver.WorkerID != "" {
		fmt.Printf("  Worker ID: %s\n", cfg.Rediver.WorkerID)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\nPress Ctrl+C to stop.")

	// Wait for shutdown
	<-ctx.Done()

	// Stop poller
	if poller != nil {
		poller.Stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := agent.Stop(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
	}

	fmt.Println("Agent stopped.")
}

func getMode(cfg *Config) string {
	if cfg.Agent.EnableCommands && len(cfg.Targets) > 0 {
		return "Hybrid (scheduled + server-controlled)"
	} else if cfg.Agent.EnableCommands {
		return "Server-Controlled"
	} else {
		return "Standalone"
	}
}

func getScanner(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	// Try native scanners first (better support for dataflow, native JSON, etc.)
	switch cfg.Name {
	case "semgrep":
		scanner := scanners.Semgrep()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "gitleaks":
		scanner := scanners.Gitleaks()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		// Wrap gitleaks in adapter to implement core.Scanner
		return &gitleaksAdapter{scanner}, nil

	case "trivy", "trivy-fs":
		scanner := scanners.TrivyFS()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-config":
		scanner := scanners.TrivyConfig()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-image":
		scanner := scanners.TrivyImage()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-full":
		scanner := scanners.TrivyFull()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil
	}

	// Fall back to generic preset scanner
	scanner, err := core.NewPresetScanner(cfg.Name)
	if err == nil {
		scanner.SetVerbose(verbose)
		return scanner, nil
	}

	// Custom scanner
	if cfg.Binary != "" {
		return core.NewBaseScanner(&core.BaseScannerConfig{
			Name:        cfg.Name,
			Binary:      cfg.Binary,
			DefaultArgs: cfg.Args,
			Timeout:     30 * time.Minute,
			OKExitCodes: []int{0, 1},
			Verbose:     verbose,
		}), nil
	}

	return nil, fmt.Errorf("unknown scanner: %s (use -list-tools to see available)", cfg.Name)
}

// gitleaksAdapter wraps gitleaks.Scanner to implement core.Scanner interface.
type gitleaksAdapter struct {
	*scanners.GitleaksScanner
}

func (a *gitleaksAdapter) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return a.GitleaksScanner.GenericScan(ctx, target, opts)
}

func getCollector(cfg CollectorConfig, verbose bool) (core.Collector, error) {
	switch cfg.Name {
	case "github":
		return core.NewGitHubCollector(&core.GitHubCollectorConfig{
			Token:   cfg.Token,
			Owner:   cfg.Owner,
			Repo:    cfg.Repo,
			Verbose: verbose,
		}), nil
	case "webhook":
		return core.NewWebhookCollector(&core.WebhookCollectorConfig{
			Verbose: verbose,
		}), nil
	default:
		return nil, fmt.Errorf("unknown collector: %s", cfg.Name)
	}
}

func printSummary(scanner string, report *ris.Report) {
	fmt.Printf("[%s] Found %d findings\n", scanner, len(report.Findings))

	// Count by severity
	severityCounts := make(map[ris.Severity]int)
	for _, f := range report.Findings {
		severityCounts[f.Severity]++
	}

	if len(severityCounts) > 0 {
		fmt.Printf("  Severity breakdown:\n")
		for _, sev := range ris.AllSeverities() {
			if count, ok := severityCounts[sev]; ok {
				fmt.Printf("    %-10s: %d\n", sev, count)
			}
		}
	}
}

// detectAsset detects the asset type and value from a target directory.
func detectAsset(target string) (ris.AssetType, string) {
	// Resolve to absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		absPath = target
	}

	// Check if it's a git repository
	gitConfigPath := filepath.Join(absPath, ".git", "config")
	if _, err := os.Stat(gitConfigPath); err == nil {
		// Read git config to get remote URL
		if remoteURL := readGitRemoteURL(gitConfigPath); remoteURL != "" {
			return ris.AssetTypeRepository, normalizeGitURL(remoteURL)
		}
	}

	// Default to using the directory name
	dirName := filepath.Base(absPath)
	return ris.AssetTypeRepository, dirName
}

// readGitRemoteURL reads the origin remote URL from a git config file.
func readGitRemoteURL(configPath string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRemoteOrigin := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[remote \"origin\"]" {
			inRemoteOrigin = true
			continue
		}

		if inRemoteOrigin {
			if strings.HasPrefix(line, "[") {
				// Reached next section
				break
			}
			if strings.HasPrefix(line, "url = ") {
				return strings.TrimPrefix(line, "url = ")
			}
		}
	}

	return ""
}

// normalizeGitURL normalizes a git URL to a standard format.
func normalizeGitURL(url string) string {
	// Convert SSH URLs to HTTPS-like format
	// git@github.com:org/repo.git -> github.com/org/repo
	if after, ok := strings.CutPrefix(url, "git@"); ok {
		url = after
		url = strings.Replace(url, ":", "/", 1)
	}

	// Remove https:// or http://
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")

	return url
}

// detectGitBranch detects the current git branch from a target directory.
func detectGitBranch(target string) string {
	// Resolve to absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		absPath = target
	}

	// Try to read .git/HEAD file
	headPath := filepath.Join(absPath, ".git", "HEAD")
	content, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}

	headContent := strings.TrimSpace(string(content))

	// HEAD file contains either:
	// 1. "ref: refs/heads/branch-name" (normal branch)
	// 2. A commit hash (detached HEAD)
	if after, ok := strings.CutPrefix(headContent, "ref: refs/heads/"); ok {
		return after
	}

	// Detached HEAD - return short commit hash
	if len(headContent) >= 7 {
		return headContent[:7]
	}

	return ""
}

// ToolInfo contains information about a scanner tool.
type ToolInfo struct {
	Name           string
	Description    string
	Binary         string
	InstallMacOS   string
	InstallLinux   string
	InstallWindows string
	InstallURL     string
}

// NativeTools defines the native scanners with installation info.
var NativeTools = []ToolInfo{
	{
		Name:           "semgrep",
		Description:    "SAST scanner with dataflow/taint tracking",
		Binary:         "semgrep",
		InstallMacOS:   "brew install semgrep",
		InstallLinux:   "pip install semgrep",
		InstallWindows: "pip install semgrep",
		InstallURL:     "https://semgrep.dev/docs/getting-started/",
	},
	{
		Name:           "gitleaks",
		Description:    "Secret detection scanner",
		Binary:         "gitleaks",
		InstallMacOS:   "brew install gitleaks",
		InstallLinux:   "brew install gitleaks  # or download from GitHub releases",
		InstallWindows: "choco install gitleaks",
		InstallURL:     "https://github.com/gitleaks/gitleaks#installing",
	},
	{
		Name:           "trivy",
		Description:    "SCA/Container/IaC scanner",
		Binary:         "trivy",
		InstallMacOS:   "brew install trivy",
		InstallLinux:   "sudo apt-get install trivy  # or brew install trivy",
		InstallWindows: "choco install trivy",
		InstallURL:     "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
	},
}

// checkAndInstallTools checks tool installation status and optionally installs them.
func checkAndInstallTools(ctx context.Context, install, verbose bool) {
	fmt.Println("Checking scanner tools installation...")
	fmt.Println()

	// Detect OS
	osType := detectOS()

	var missingTools []ToolInfo
	var installedTools []ToolInfo

	for _, tool := range NativeTools {
		installed, version, _ := checkBinaryInstalled(ctx, tool.Binary)

		if installed {
			fmt.Printf("  ✓ %-12s %s (installed: %s)\n", tool.Name, tool.Description, version)
			installedTools = append(installedTools, tool)
		} else {
			fmt.Printf("  ✗ %-12s %s (NOT INSTALLED)\n", tool.Name, tool.Description)
			missingTools = append(missingTools, tool)
		}
	}

	fmt.Println()

	if len(missingTools) == 0 {
		fmt.Println("All tools are installed! Ready to scan.")
		return
	}

	fmt.Printf("Missing %d tool(s).\n\n", len(missingTools))

	if install {
		// Interactive installation
		installToolsInteractive(ctx, missingTools, osType)
	} else {
		// Show installation instructions
		fmt.Println("Installation instructions:")
		fmt.Println()

		for _, tool := range missingTools {
			fmt.Printf("  %s:\n", tool.Name)
			switch osType {
			case "darwin":
				fmt.Printf("    macOS:   %s\n", tool.InstallMacOS)
			case "linux":
				fmt.Printf("    Linux:   %s\n", tool.InstallLinux)
			case "windows":
				fmt.Printf("    Windows: %s\n", tool.InstallWindows)
			default:
				fmt.Printf("    macOS:   %s\n", tool.InstallMacOS)
				fmt.Printf("    Linux:   %s\n", tool.InstallLinux)
				fmt.Printf("    Windows: %s\n", tool.InstallWindows)
			}
			fmt.Printf("    Docs:    %s\n", tool.InstallURL)
			fmt.Println()
		}

		fmt.Println("Run with -install-tools to install interactively.")
	}
}

// installToolsInteractive installs missing tools interactively.
func installToolsInteractive(ctx context.Context, tools []ToolInfo, osType string) {
	reader := bufio.NewReader(os.Stdin)

	for _, tool := range tools {
		var installCmd string
		switch osType {
		case "darwin":
			installCmd = tool.InstallMacOS
		case "linux":
			installCmd = tool.InstallLinux
		case "windows":
			installCmd = tool.InstallWindows
		default:
			installCmd = tool.InstallMacOS
		}

		fmt.Printf("Install %s? [y/N] ", tool.Name)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input != "y" && input != "yes" {
			fmt.Printf("  Skipped %s\n\n", tool.Name)
			continue
		}

		fmt.Printf("  Installing %s...\n", tool.Name)
		fmt.Printf("  Command: %s\n", installCmd)

		// Parse and execute command
		parts := strings.Fields(installCmd)
		if len(parts) == 0 {
			fmt.Printf("  Error: invalid install command\n\n")
			continue
		}

		// Execute the install command
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("  Error installing %s: %v\n", tool.Name, err)
			fmt.Printf("  Please install manually: %s\n\n", tool.InstallURL)
			continue
		}

		// Verify installation
		installed, version, _ := checkBinaryInstalled(ctx, tool.Binary)
		if installed {
			fmt.Printf("  ✓ %s installed successfully (version: %s)\n\n", tool.Name, version)
		} else {
			fmt.Printf("  Warning: %s may not be in PATH. Please verify installation.\n\n", tool.Name)
		}
	}
}

// detectOS detects the current operating system.
func detectOS() string {
	return runtime.GOOS
}

// checkBinaryInstalled checks if a binary is installed.
func checkBinaryInstalled(ctx context.Context, binary string) (bool, string, error) {
	cmd := exec.CommandContext(ctx, binary, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", err
	}

	// Parse version from output
	version := parseToolVersion(binary, string(output))
	return true, version, nil
}

// parseToolVersion extracts clean version string from tool output.
func parseToolVersion(tool, output string) string {
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")

	// Get first non-empty, non-warning line
	var firstLine string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip warning lines
		if strings.Contains(line, "WARNING") || strings.Contains(line, "warning") {
			continue
		}
		firstLine = line
		break
	}

	if firstLine == "" && len(lines) > 0 {
		firstLine = strings.TrimSpace(lines[0])
	}

	// Tool-specific parsing
	switch tool {
	case "semgrep":
		// semgrep output is noisy - version is usually the last line that looks like a version
		// e.g., "1.135.0"
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			if isVersionString(line) {
				return line
			}
		}
		// Fallback: try to find version in any line
		for _, line := range lines {
			for _, part := range strings.Fields(line) {
				if isVersionString(part) {
					return part
				}
			}
		}
		return firstLine

	case "gitleaks":
		// gitleaks output: "gitleaks version 8.28.0"
		if strings.Contains(firstLine, "version") {
			parts := strings.Fields(firstLine)
			for i, p := range parts {
				if p == "version" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
		return firstLine

	case "trivy":
		// trivy output: "Version: 0.67.2"
		if strings.HasPrefix(firstLine, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(firstLine, "Version:"))
		}
		return firstLine

	default:
		return firstLine
	}
}

// isVersionString checks if a string looks like a version number.
func isVersionString(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Version strings typically start with a digit
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	// Or start with 'v' followed by digit
	if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		return true
	}
	return false
}
