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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rediverio/rediver-sdk/sdk/client"
	"github.com/rediverio/rediver-sdk/sdk/core"
	"github.com/rediverio/rediver-sdk/sdk/ris"
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
		SourceID string        `yaml:"source_id"` // For tenant tracking
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
	sourceID := flag.String("source-id", "", "Source ID for tracking (or REDIVER_SOURCE_ID env)")
	push := flag.Bool("push", false, "Push results to Rediver")
	daemon := flag.Bool("daemon", false, "Run in daemon mode")
	enableCommands := flag.Bool("enable-commands", false, "Enable server command polling (daemon mode)")
	standalone := flag.Bool("standalone", false, "Standalone mode - no server communication")
	verbose := flag.Bool("verbose", false, "Verbose output")
	listTools := flag.Bool("list-tools", false, "List available tools")
	showVersion := flag.Bool("version", false, "Show version")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	outputFile := flag.String("output", "", "Output file path (instead of stdout)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("%s version %s\n", appName, appVersion)
		os.Exit(0)
	}

	if *listTools {
		fmt.Println("Available preset scanners:")
		fmt.Println()
		for _, name := range core.ListPresetScanners() {
			cfg := core.PresetScanners[name]
			fmt.Printf("  %-15s - %s\n", name, strings.Join(cfg.Capabilities, ", "))
		}
		fmt.Println()
		fmt.Println("Usage examples:")
		fmt.Println("  rediver-agent -tool semgrep -target ./src -push")
		fmt.Println("  rediver-agent -tools semgrep,gitleaks -target . -push")
		fmt.Println("  rediver-agent -daemon -config agent.yaml")
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
		cfg.Rediver.SourceID = getEnvOrFlag(*sourceID, "REDIVER_SOURCE_ID")
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
			SourceID: cfg.Rediver.SourceID,
			Timeout:  cfg.Rediver.Timeout,
			Verbose:  cfg.Agent.Verbose,
		})
		pusher = apiClient

		// Test connection
		if err := pusher.TestConnection(ctx); err != nil {
			fmt.Printf("Warning: Could not connect to Rediver API: %v\n", err)
		} else if cfg.Agent.Verbose {
			fmt.Println("Connected to Rediver API")
			if cfg.Rediver.SourceID != "" {
				fmt.Printf("Source ID: %s\n", cfg.Rediver.SourceID)
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
		runOnce(ctx, &cfg, pusher, *push, *outputJSON, *outputFile)
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

func runOnce(ctx context.Context, cfg *Config, pusher core.Pusher, push, outputJSON bool, outputFile string) {
	parsers := core.NewParserRegistry()
	var allReports []*ris.Report

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

		// Scan each target
		for _, target := range cfg.Targets {
			fmt.Printf("[%s] Scanning %s...\n", scanner.Name(), target)

			result, err := scanner.Scan(ctx, target, &core.ScanOptions{
				TargetDir: target,
				Verbose:   cfg.Agent.Verbose,
			})

			if err != nil {
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

			report, err := parser.Parse(ctx, result.RawOutput, &core.ParseOptions{
				ToolName: scanner.Name(),
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

			// Push to Rediver
			if push && pusher != nil && len(report.Findings) > 0 {
				fmt.Printf("[%s] Pushing %d findings to Rediver...\n", scanner.Name(), len(report.Findings))
				pushResult, err := pusher.PushFindings(ctx, report)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] Push failed: %v\n", scanner.Name(), err)
				} else {
					fmt.Printf("[%s] Pushed: %d created, %d updated\n",
						scanner.Name(), pushResult.FindingsCreated, pushResult.FindingsUpdated)
				}
			}
		}
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
	if cfg.Rediver.SourceID != "" {
		fmt.Printf("  Source ID: %s\n", cfg.Rediver.SourceID)
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
	// Try preset first
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
