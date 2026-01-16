// Package main provides an integration test example for the Rediver SDK.
// This example demonstrates how to:
// 1. Connect to the Rediver API
// 2. Send heartbeat
// 3. Push findings and assets
// 4. Poll for commands
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rediverio/rediver-sdk/pkg/client"
	"github.com/rediverio/rediver-sdk/pkg/core"
	"github.com/rediverio/rediver-sdk/pkg/ris"
)

func main() {
	// Parse command line flags
	baseURL := flag.String("url", "http://localhost:8080", "Rediver API base URL")
	apiKey := flag.String("api-key", "", "API key for authentication")
	workerID := flag.String("worker-id", "", "Worker ID (optional)")
	verbose := flag.Bool("verbose", true, "Enable verbose output")
	flag.Parse()

	// Check required flags
	if *apiKey == "" {
		// Try to get from environment
		*apiKey = os.Getenv("REDIVER_API_KEY")
		if *apiKey == "" {
			log.Fatal("API key is required. Use -api-key flag or REDIVER_API_KEY environment variable")
		}
	}

	// Create client
	cfg := &client.Config{
		BaseURL:    *baseURL,
		APIKey:     *apiKey,
		WorkerID:   *workerID,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
		Verbose:    *verbose,
	}

	c := client.New(cfg)
	ctx := context.Background()

	fmt.Println("=== Rediver SDK Integration Test ===")
	fmt.Printf("Base URL: %s\n", *baseURL)
	fmt.Println()

	// Test 1: Connection test (heartbeat)
	fmt.Println("1. Testing connection (heartbeat)...")
	if err := testHeartbeat(ctx, c); err != nil {
		log.Printf("   ✗ Heartbeat failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Heartbeat successful")
	}
	fmt.Println()

	// Test 2: Push findings
	fmt.Println("2. Testing push findings...")
	if err := testPushFindings(ctx, c); err != nil {
		log.Printf("   ✗ Push findings failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push findings successful")
	}
	fmt.Println()

	// Test 3: Push assets
	fmt.Println("3. Testing push assets...")
	if err := testPushAssets(ctx, c); err != nil {
		log.Printf("   ✗ Push assets failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push assets successful")
	}
	fmt.Println()

	// Test 4: Push combined (findings + assets)
	fmt.Println("4. Testing push combined report...")
	if err := testPushCombined(ctx, c); err != nil {
		log.Printf("   ✗ Push combined failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push combined successful")
	}
	fmt.Println()

	// Test 5: Poll commands
	fmt.Println("5. Testing poll commands...")
	if err := testPollCommands(ctx, c); err != nil {
		log.Printf("   ✗ Poll commands failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Poll commands successful")
	}
	fmt.Println()

	fmt.Println("=== Integration Test Complete ===")
}

func testHeartbeat(ctx context.Context, c *client.Client) error {
	status := &core.AgentStatus{
		Name:     "integration-test",
		Status:   core.AgentStateRunning,
		Message:  "Integration test running",
		Scanners: []string{"semgrep", "trivy"},
		Uptime:   100,
	}

	return c.SendHeartbeat(ctx, status)
}

func testPushFindings(ctx context.Context, c *client.Client) error {
	report := createSampleFindingsReport()

	result, err := c.PushFindings(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Findings created: %d, updated: %d\n", result.FindingsCreated, result.FindingsUpdated)
	return nil
}

func testPushAssets(ctx context.Context, c *client.Client) error {
	report := createSampleAssetsReport()

	result, err := c.PushAssets(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Assets created: %d, updated: %d\n", result.AssetsCreated, result.AssetsUpdated)
	return nil
}

func testPushCombined(ctx context.Context, c *client.Client) error {
	report := createCombinedReport()

	result, err := c.PushFindings(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Assets created: %d, Findings created: %d\n", result.AssetsCreated, result.FindingsCreated)
	return nil
}

func testPollCommands(ctx context.Context, c *client.Client) error {
	commands, err := c.PollCommands(ctx, 10)
	if err != nil {
		return err
	}

	fmt.Printf("   Pending commands: %d\n", len(commands))
	for _, cmd := range commands {
		fmt.Printf("   - Command: %s (type: %s, priority: %s)\n", cmd.ID, cmd.Type, cmd.Priority)
	}

	return nil
}

// createSampleFindingsReport creates a sample report with findings.
func createSampleFindingsReport() *ris.Report {
	now := time.Now()

	report := ris.NewReport()
	report.Metadata = ris.ReportMetadata{
		ID:         fmt.Sprintf("scan-%d", now.Unix()),
		Timestamp:  now,
		DurationMs: 5000,
		SourceType: "scanner",
		SourceRef:  "integration-test",
	}

	report.Tool = &ris.Tool{
		Name:    "semgrep",
		Version: "1.50.0",
		Vendor:  "Semgrep Inc.",
	}

	// Add sample findings
	report.Findings = []ris.Finding{
		{
			ID:          "finding-1",
			Type:        ris.FindingTypeVulnerability,
			Title:       "SQL Injection vulnerability",
			Description: "User input is directly concatenated into SQL query without proper sanitization.",
			Severity:    ris.SeverityHigh,
			Confidence:  90,
			Category:    "security",
			RuleID:      "sql-injection",
			RuleName:    "SQL Injection Detection",
			Location: &ris.FindingLocation{
				Path:        "src/api/users.go",
				StartLine:   45,
				EndLine:     48,
				StartColumn: 1,
				EndColumn:   50,
				Snippet:     `query := "SELECT * FROM users WHERE id = " + userID`,
			},
			Vulnerability: &ris.VulnerabilityDetails{
				CWEID: "CWE-89",
			},
			Remediation: &ris.Remediation{
				Recommendation: "Use parameterized queries instead of string concatenation",
				Steps: []string{
					"Replace string concatenation with prepared statements",
					"Use query parameters for user input",
					"Validate and sanitize all user inputs",
				},
				Effort: "low",
			},
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
			},
			Tags: []string{"owasp-top-10", "injection"},
		},
		{
			ID:          "finding-2",
			Type:        ris.FindingTypeVulnerability,
			Title:       "Hardcoded credentials detected",
			Description: "API key is hardcoded in the source code.",
			Severity:    ris.SeverityCritical,
			Confidence:  95,
			Category:    "security",
			RuleID:      "hardcoded-secret",
			Location: &ris.FindingLocation{
				Path:      "src/config/config.go",
				StartLine: 12,
				EndLine:   12,
				Snippet:   `apiKey := "sk_live_xxxxxxxxxxxxx"`,
			},
			Secret: &ris.SecretDetails{
				SecretType:  "api_key",
				Service:     "stripe",
				MaskedValue: "sk_live_xxx...xxx",
				Length:      32,
			},
			Tags: []string{"secrets", "credentials"},
		},
		{
			ID:          "finding-3",
			Type:        ris.FindingTypeVulnerability,
			Title:       "Cross-Site Scripting (XSS)",
			Description: "User input is rendered without escaping in HTML template.",
			Severity:    ris.SeverityMedium,
			Confidence:  80,
			RuleID:      "xss-reflected",
			Location: &ris.FindingLocation{
				Path:      "templates/user.html",
				StartLine: 25,
				Snippet:   `<div>{{ .UserInput }}</div>`,
			},
			Vulnerability: &ris.VulnerabilityDetails{
				CWEID: "CWE-79",
			},
		},
	}

	return report
}

// createSampleAssetsReport creates a sample report with assets only.
func createSampleAssetsReport() *ris.Report {
	now := time.Now()

	report := ris.NewReport()
	report.Metadata = ris.ReportMetadata{
		ID:         fmt.Sprintf("asset-discovery-%d", now.Unix()),
		Timestamp:  now,
		SourceType: "collector",
	}

	report.Tool = &ris.Tool{
		Name:    "asset-collector",
		Version: "1.0.0",
	}

	report.Assets = []ris.Asset{
		{
			ID:          "asset-1",
			Type:        ris.AssetTypeRepository,
			Value:       "github.com/example/webapp",
			Name:        "Web Application",
			Description: "Main web application repository",
			Criticality: ris.CriticalityHigh,
			Tags:        []string{"production", "frontend"},
			Technical: &ris.AssetTechnical{
				Repository: &ris.RepositoryTechnical{
					Platform:      "github",
					Owner:         "example",
					Name:          "webapp",
					DefaultBranch: "main",
					Visibility:    "private",
					URL:           "https://github.com/example/webapp",
				},
			},
		},
		{
			ID:          "asset-2",
			Type:        ris.AssetTypeDomain,
			Value:       "api.example.com",
			Name:        "API Domain",
			Criticality: ris.CriticalityCritical,
			Tags:        []string{"production", "api"},
			Technical: &ris.AssetTechnical{
				Domain: &ris.DomainTechnical{
					Registrar:   "Cloudflare",
					Nameservers: []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
				},
			},
		},
		{
			ID:          "asset-3",
			Type:        ris.AssetTypeIPAddress,
			Value:       "10.0.1.100",
			Name:        "Database Server",
			Criticality: ris.CriticalityCritical,
			Tags:        []string{"internal", "database"},
			Technical: &ris.AssetTechnical{
				IPAddress: &ris.IPAddressTechnical{
					Version:  4,
					Hostname: "db-primary.internal",
					Ports: []ris.PortInfo{
						{Port: 5432, Protocol: "tcp", Service: "postgresql", State: "open"},
					},
				},
			},
		},
	}

	return report
}

// createCombinedReport creates a report with both assets and findings.
func createCombinedReport() *ris.Report {
	now := time.Now()

	report := ris.NewReport()
	report.Metadata = ris.ReportMetadata{
		ID:         fmt.Sprintf("full-scan-%d", now.Unix()),
		Timestamp:  now,
		DurationMs: 30000,
		SourceType: "scanner",
	}

	report.Tool = &ris.Tool{
		Name:    "trivy",
		Version: "0.48.0",
		Vendor:  "Aqua Security",
	}

	// Add assets
	report.Assets = []ris.Asset{
		{
			ID:          "container-1",
			Type:        ris.AssetTypeContainer,
			Value:       "docker.io/example/app:v1.2.3",
			Name:        "Application Container",
			Criticality: ris.CriticalityHigh,
			Tags:        []string{"production", "container"},
		},
	}

	// Add findings referencing the asset
	report.Findings = []ris.Finding{
		{
			ID:          "vuln-1",
			Type:        ris.FindingTypeVulnerability,
			Title:       "CVE-2024-1234: Critical vulnerability in openssl",
			Description: "A critical vulnerability in OpenSSL allows remote code execution.",
			Severity:    ris.SeverityCritical,
			Confidence:  100,
			RuleID:      "CVE-2024-1234",
			AssetRef:    "container-1", // Reference to asset
			Vulnerability: &ris.VulnerabilityDetails{
				CVEID:            "CVE-2024-1234",
				CWEID:            "CWE-119",
				CVSSVersion:      "3.1",
				CVSSScore:        9.8,
				CVSSVector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Package:          "openssl",
				AffectedVersion:  "1.1.1",
				FixedVersion:     "1.1.1w",
				Ecosystem:        "debian",
				ExploitAvailable: true,
			},
			Remediation: &ris.Remediation{
				Recommendation: "Upgrade openssl to version 1.1.1w or later",
				FixAvailable:   true,
			},
		},
		{
			ID:       "vuln-2",
			Type:     ris.FindingTypeVulnerability,
			Title:    "CVE-2024-5678: High severity in curl",
			Severity: ris.SeverityHigh,
			RuleID:   "CVE-2024-5678",
			AssetRef: "container-1",
			Vulnerability: &ris.VulnerabilityDetails{
				CVEID:           "CVE-2024-5678",
				CVSSScore:       7.5,
				Package:         "curl",
				AffectedVersion: "7.88.0",
				FixedVersion:    "7.88.1",
			},
		},
	}

	return report
}
