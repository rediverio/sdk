package nuclei

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/exploopio/sdk/pkg/eis"
)

// Parser converts Nuclei output to EIS format.
type Parser struct {
	Verbose bool
}

// NewParser creates a new Nuclei parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts Nuclei JSON Lines output to EIS Report.
func (p *Parser) Parse(data []byte, target string) (*eis.Report, error) {
	results, err := p.parseJSONLines(data)
	if err != nil {
		return nil, err
	}

	return p.toRISReport(results, target), nil
}

// ParseResults converts parsed Nuclei results to EIS Report.
func (p *Parser) ParseResults(results []Result, target string) *eis.Report {
	return p.toRISReport(results, target)
}

// parseJSONLines parses Nuclei's JSON Lines output format.
func (p *Parser) parseJSONLines(data []byte) ([]Result, error) {
	var results []Result

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Increase buffer size for large responses
	const maxCapacity = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var result Result
		if err := json.Unmarshal(line, &result); err != nil {
			if p.Verbose {
				fmt.Printf("[nuclei-parser] Warning: Failed to parse line: %v\n", err)
			}
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output: %w", err)
	}

	return results, nil
}

// toRISReport converts Nuclei results to EIS Report format.
func (p *Parser) toRISReport(results []Result, target string) *eis.Report {
	report := eis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	report.Tool = &eis.Tool{
		Name:         "nuclei",
		Vendor:       "ProjectDiscovery",
		InfoURL:      "https://github.com/projectdiscovery/nuclei",
		Capabilities: []string{"dast", "vulnerability_scanning", "misconfiguration_detection"},
	}

	// Track unique assets
	assetMap := make(map[string]string) // host -> asset ID

	for i, result := range results {
		// Create or get asset for this result
		assetID := p.getOrCreateAsset(report, result, assetMap)

		// Create finding
		finding := p.toRISFinding(result, assetID, i)
		report.Findings = append(report.Findings, finding)
	}

	return report
}

// getOrCreateAsset creates or retrieves an asset for the result.
func (p *Parser) getOrCreateAsset(report *eis.Report, result Result, assetMap map[string]string) string {
	// Determine asset key (host or URL)
	key := result.Host
	if result.URL != "" {
		key = result.URL
	}

	// Check if asset already exists
	if assetID, exists := assetMap[key]; exists {
		return assetID
	}

	// Create new asset
	assetID := fmt.Sprintf("asset-%d", len(report.Assets))
	assetMap[key] = assetID

	assetType := eis.AssetTypeDomain
	assetValue := result.Host

	// Determine asset type based on result
	if result.IP != "" {
		assetType = eis.AssetTypeIPAddress
		assetValue = result.IP
	} else if result.URL != "" {
		assetType = eis.AssetTypeService
		assetValue = result.URL
	}

	asset := eis.Asset{
		ID:         assetID,
		Type:       assetType,
		Value:      assetValue,
		Name:       key,
		Confidence: 90,
		Properties: make(eis.Properties),
	}

	// Add technical details
	if result.Port != "" {
		asset.Properties["port"] = result.Port
	}
	if result.IP != "" {
		asset.Properties["ip"] = result.IP
	}

	report.Assets = append(report.Assets, asset)
	return assetID
}

// toRISFinding converts a Nuclei result to EIS Finding.
func (p *Parser) toRISFinding(result Result, assetRef string, index int) eis.Finding {
	findingID := fmt.Sprintf("finding-%d", index)

	// Determine finding type
	findingType := eis.FindingTypeVulnerability
	if containsAny(result.Info.Tags, "misconfig", "config", "exposure") {
		findingType = eis.FindingTypeMisconfiguration
	}

	// Map severity
	severity := eis.Severity(GetRISSeverity(result.Info.Severity))

	// Build title
	title := result.Info.Name
	if title == "" {
		title = result.TemplateID
	}

	finding := eis.Finding{
		ID:          findingID,
		Type:        findingType,
		Title:       title,
		Description: result.Info.Description,
		Severity:    severity,
		Confidence:  85, // Nuclei templates are generally reliable
		Category:    getCategoryFromTags(result.Info.Tags),
		RuleID:      result.TemplateID,
		RuleName:    result.Info.Name,
		AssetRef:    assetRef,
		Tags:        result.Info.Tags,
		References:  result.Info.Reference,
		Fingerprint: p.generateFingerprint(result),
		Properties:  make(eis.Properties),
	}

	// Set location based on matched URL
	if result.Matched != "" || result.URL != "" {
		location := result.Matched
		if location == "" {
			location = result.URL
		}
		finding.Location = &eis.FindingLocation{
			Path: location,
		}
	}

	// Add vulnerability details if classification exists
	if result.Info.Classification != nil {
		finding.Vulnerability = &eis.VulnerabilityDetails{}

		if len(result.Info.Classification.CVEId) > 0 {
			finding.Vulnerability.CVEID = result.Info.Classification.CVEId[0]
		}
		if len(result.Info.Classification.CWEId) > 0 {
			finding.Vulnerability.CWEIDs = result.Info.Classification.CWEId
			finding.Vulnerability.CWEID = result.Info.Classification.CWEId[0]
		}
		if result.Info.Classification.CVSSScore > 0 {
			finding.Vulnerability.CVSSScore = result.Info.Classification.CVSSScore
			finding.Vulnerability.CVSSVector = result.Info.Classification.CVSSMetrics
		}
		if result.Info.Classification.EPSSScore > 0 {
			finding.Vulnerability.EPSSScore = result.Info.Classification.EPSSScore
			finding.Vulnerability.EPSSPercentile = result.Info.Classification.EPSSPercentile
		}
	}

	// Add remediation if available
	if result.Info.Remediation != "" {
		finding.Remediation = &eis.Remediation{
			Recommendation: result.Info.Remediation,
		}
	}

	// Store additional data in properties
	if result.Request != "" {
		finding.Properties["request"] = truncateString(result.Request, 5000)
	}
	if result.Response != "" {
		finding.Properties["response"] = truncateString(result.Response, 10000)
	}
	if result.CurlCommand != "" {
		finding.Properties["curl_command"] = result.CurlCommand
	}
	if len(result.ExtractedResults) > 0 {
		finding.Properties["extracted_results"] = result.ExtractedResults
	}
	if result.MatcherName != "" {
		finding.Properties["matcher_name"] = result.MatcherName
	}
	if result.Interaction != nil {
		finding.Properties["interaction"] = map[string]any{
			"protocol":       result.Interaction.Protocol,
			"unique_id":      result.Interaction.UniqueID,
			"remote_address": result.Interaction.RemoteAddress,
		}
	}

	// Set author if available
	if len(result.Info.Author) > 0 {
		finding.Author = strings.Join(result.Info.Author, ", ")
	}

	now := time.Now()
	finding.FirstSeenAt = &now
	finding.LastSeenAt = &now

	return finding
}

// generateFingerprint creates a unique fingerprint for a finding.
func (p *Parser) generateFingerprint(result Result) string {
	// Combine key identifying fields
	data := fmt.Sprintf("%s|%s|%s|%s",
		result.TemplateID,
		result.Host,
		result.Matched,
		result.MatcherName,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// getCategoryFromTags extracts the primary category from tags.
func getCategoryFromTags(tags []string) string {
	// Priority order for categories
	priorities := []string{
		"cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi",
		"auth-bypass", "takeover", "exposure", "misconfig",
		"default-login", "creds", "injection",
	}

	for _, priority := range priorities {
		for _, tag := range tags {
			if strings.EqualFold(tag, priority) {
				return tag
			}
		}
	}

	// Return first tag if no priority match
	if len(tags) > 0 {
		return tags[0]
	}
	return "vulnerability"
}

// containsAny checks if any of the search strings exist in the slice.
func containsAny(slice []string, searches ...string) bool {
	for _, s := range slice {
		for _, search := range searches {
			if strings.EqualFold(s, search) {
				return true
			}
		}
	}
	return false
}

// truncateString truncates a string to the specified length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}
