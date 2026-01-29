package codeql

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rediverio/sdk/pkg/ris"
)

// =============================================================================
// Parser - Convert CodeQL SARIF to RIS Findings with full DataFlow support
// =============================================================================

// Parser converts CodeQL SARIF output to RIS format.
type Parser struct {
	// Rules from the SARIF run (for metadata lookup)
	rules map[string]*Rule
}

// NewParser creates a new CodeQL SARIF parser.
func NewParser() *Parser {
	return &Parser{
		rules: make(map[string]*Rule),
	}
}

// Parse parses CodeQL SARIF JSON output to RIS findings.
func (p *Parser) Parse(data []byte) ([]*ris.Finding, error) {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse CodeQL SARIF: %w", err)
	}

	var findings []*ris.Finding

	for _, run := range report.Runs {
		// Index rules for lookup
		p.indexRules(&run)

		// Parse results
		for _, result := range run.Results {
			finding := p.convertResult(&result)
			if finding != nil {
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// ParseToReport parses CodeQL SARIF to a complete RIS report.
func (p *Parser) ParseToReport(data []byte) (*ris.Report, error) {
	findingPtrs, err := p.Parse(data)
	if err != nil {
		return nil, err
	}

	// Convert []*Finding to []Finding
	findings := make([]ris.Finding, 0, len(findingPtrs))
	for _, f := range findingPtrs {
		if f != nil {
			findings = append(findings, *f)
		}
	}

	report := &ris.Report{
		Version: "1.0",
		Tool: &ris.Tool{
			Name:    "codeql",
			Version: p.getToolVersion(data),
		},
		Findings: findings,
	}

	return report, nil
}

// indexRules indexes rules from the SARIF run for metadata lookup.
func (p *Parser) indexRules(run *Run) {
	// Index driver rules
	for i := range run.Tool.Driver.Rules {
		rule := &run.Tool.Driver.Rules[i]
		p.rules[rule.ID] = rule
	}

	// Index extension rules
	for _, ext := range run.Tool.Extensions {
		for i := range ext.Rules {
			rule := &ext.Rules[i]
			p.rules[rule.ID] = rule
		}
	}
}

// convertResult converts a SARIF result to an RIS finding.
func (p *Parser) convertResult(result *Result) *ris.Finding {
	// Get rule metadata
	rule := p.rules[result.RuleID]

	finding := &ris.Finding{
		Type:        ris.FindingTypeVulnerability,
		RuleID:      result.RuleID,
		Title:       p.buildTitle(result, rule),
		Description: result.Message.Text,
		Severity:    p.convertLevel(result.Level, rule),
		Confidence:  p.getConfidence(rule),
	}

	// Set CWE IDs
	if rule != nil && len(rule.Properties.CWEIDs) > 0 {
		finding.Vulnerability = &ris.VulnerabilityDetails{
			CWEIDs: p.normalizeCWEs(rule.Properties.CWEIDs),
		}
	}

	// Set location
	if len(result.Locations) > 0 {
		finding.Location = p.convertLocation(&result.Locations[0])
	}

	// Set related locations
	if len(result.RelatedLocations) > 0 {
		for _, loc := range result.RelatedLocations {
			finding.RelatedLocations = append(finding.RelatedLocations, p.convertLocation(&loc))
		}
	}

	// Set fingerprints
	if len(result.PartialFingerprints) > 0 {
		finding.PartialFingerprints = result.PartialFingerprints
	}
	if len(result.Fingerprints) > 0 {
		for k, v := range result.Fingerprints {
			if finding.Fingerprint == "" {
				finding.Fingerprint = v
			}
			if finding.PartialFingerprints == nil {
				finding.PartialFingerprints = make(map[string]string)
			}
			finding.PartialFingerprints[k] = v
		}
	}

	// *** KEY FEATURE: Convert CodeFlows to DataFlow ***
	// This is where we get the full taint tracking path from CodeQL
	if len(result.CodeFlows) > 0 {
		finding.DataFlow = p.convertCodeFlows(result.CodeFlows)
	}

	// Set tags from rule properties
	if rule != nil && len(rule.Properties.Tags) > 0 {
		finding.Tags = rule.Properties.Tags
	}

	// Set references
	if rule != nil && rule.Help != nil {
		finding.References = p.extractReferences(rule.Help.Markdown)
	}

	return finding
}

// convertCodeFlows converts SARIF codeFlows to RIS DataFlow.
// This is the main function for extracting dataflow/taint tracking information.
func (p *Parser) convertCodeFlows(codeFlows []CodeFlow) *ris.DataFlow {
	if len(codeFlows) == 0 {
		return nil
	}

	// Use the first code flow (most common case)
	cf := codeFlows[0]

	df := &ris.DataFlow{
		Tainted: true,
	}

	// Build summary from message
	if cf.Message != nil {
		df.Summary = cf.Message.Text
	}

	// Process thread flows
	for _, tf := range cf.ThreadFlows {
		locations := tf.Locations
		numLocs := len(locations)

		if numLocs == 0 {
			continue
		}

		// Determine interprocedural/cross-file
		files := make(map[string]bool)
		functions := make(map[string]bool)

		for i, tfl := range locations {
			loc := p.convertThreadFlowLocation(&tfl, i, numLocs)
			if loc == nil {
				continue
			}

			// Track files and functions
			if loc.Path != "" {
				files[loc.Path] = true
			}
			if loc.Function != "" {
				functions[loc.Function] = true
			}

			// Categorize by position and kinds
			switch {
			case i == 0 || p.isSource(&tfl):
				loc.Type = ris.DataFlowLocationSource
				loc.TaintState = "tainted"
				df.Sources = append(df.Sources, *loc)
			case i == numLocs-1 || p.isSink(&tfl):
				loc.Type = ris.DataFlowLocationSink
				df.Sinks = append(df.Sinks, *loc)
			case p.isSanitizer(&tfl):
				loc.Type = ris.DataFlowLocationSanitizer
				loc.TaintState = "sanitized"
				df.Sanitizers = append(df.Sanitizers, *loc)
			default:
				loc.Type = ris.DataFlowLocationPropagator
				df.Intermediates = append(df.Intermediates, *loc)
			}

			// Build call path
			if loc.Function != "" {
				df.CallPath = append(df.CallPath, loc.Function)
			}
		}

		// Set cross-file and interprocedural flags
		df.CrossFile = len(files) > 1
		df.Interprocedural = len(functions) > 1
	}

	// Build summary if not provided
	if df.Summary == "" {
		df.Summary = p.buildDataFlowSummary(df)
	}

	return df
}

// convertThreadFlowLocation converts a SARIF threadFlowLocation to RIS DataFlowLocation.
func (p *Parser) convertThreadFlowLocation(tfl *ThreadFlowLocation, index, total int) *ris.DataFlowLocation {
	if tfl.Location == nil || tfl.Location.PhysicalLocation == nil {
		return nil
	}

	loc := &ris.DataFlowLocation{
		Index: index,
	}

	physLoc := tfl.Location.PhysicalLocation

	// File path
	if physLoc.ArtifactLocation != nil {
		loc.Path = physLoc.ArtifactLocation.URI
	}

	// Region (line/column)
	if physLoc.Region != nil {
		loc.Line = physLoc.Region.StartLine
		loc.EndLine = physLoc.Region.EndLine
		loc.Column = physLoc.Region.StartColumn
		loc.EndColumn = physLoc.Region.EndColumn

		// Snippet
		if physLoc.Region.Snippet != nil {
			loc.Content = physLoc.Region.Snippet.Text
		}
	}

	// Context region (broader snippet)
	if physLoc.ContextRegion != nil && physLoc.ContextRegion.Snippet != nil {
		// Use context region if main snippet is empty
		if loc.Content == "" {
			loc.Content = physLoc.ContextRegion.Snippet.Text
		}
	}

	// Logical location (function/class)
	if len(tfl.Location.LogicalLocations) > 0 {
		logLoc := tfl.Location.LogicalLocations[0]
		loc.Function = logLoc.Name
		if logLoc.FullyQualifiedName != "" {
			// Extract class from FQN
			parts := strings.Split(logLoc.FullyQualifiedName, ".")
			if len(parts) > 1 {
				loc.Class = strings.Join(parts[:len(parts)-1], ".")
			}
		}
		if logLoc.Kind == "module" || logLoc.Kind == "namespace" {
			loc.Module = logLoc.Name
		}
	}

	// Message as notes
	if tfl.Location.Message != nil {
		loc.Notes = tfl.Location.Message.Text
	}

	// Importance
	if tfl.Importance != "" {
		// Map to RIS importance: essential, important, unimportant
		loc.Notes = tfl.Importance + ": " + loc.Notes
	}

	// Determine type from kinds
	for _, kind := range tfl.Kinds {
		switch kind {
		case "source":
			loc.Type = ris.DataFlowLocationSource
			loc.TaintState = "tainted"
		case "sink":
			loc.Type = ris.DataFlowLocationSink
		case "sanitizer":
			loc.Type = ris.DataFlowLocationSanitizer
			loc.TaintState = "sanitized"
		}
	}

	return loc
}

// isSource checks if a thread flow location is a source.
func (p *Parser) isSource(tfl *ThreadFlowLocation) bool {
	for _, k := range tfl.Kinds {
		if k == "source" {
			return true
		}
	}
	return false
}

// isSink checks if a thread flow location is a sink.
func (p *Parser) isSink(tfl *ThreadFlowLocation) bool {
	for _, k := range tfl.Kinds {
		if k == "sink" {
			return true
		}
	}
	return false
}

// isSanitizer checks if a thread flow location is a sanitizer.
func (p *Parser) isSanitizer(tfl *ThreadFlowLocation) bool {
	for _, k := range tfl.Kinds {
		if k == "sanitizer" {
			return true
		}
	}
	return false
}

// convertLocation converts a SARIF location to RIS FindingLocation.
func (p *Parser) convertLocation(loc *Location) *ris.FindingLocation {
	if loc == nil || loc.PhysicalLocation == nil {
		return nil
	}

	physLoc := loc.PhysicalLocation
	result := &ris.FindingLocation{}

	// File path
	if physLoc.ArtifactLocation != nil {
		result.Path = physLoc.ArtifactLocation.URI
	}

	// Region
	if physLoc.Region != nil {
		result.StartLine = physLoc.Region.StartLine
		result.EndLine = physLoc.Region.EndLine
		result.StartColumn = physLoc.Region.StartColumn
		result.EndColumn = physLoc.Region.EndColumn

		if physLoc.Region.Snippet != nil {
			result.Snippet = physLoc.Region.Snippet.Text
		}
	}

	// Context region
	if physLoc.ContextRegion != nil && physLoc.ContextRegion.Snippet != nil {
		result.ContextSnippet = physLoc.ContextRegion.Snippet.Text
	}

	// Logical location
	if len(loc.LogicalLocations) > 0 {
		logLoc := loc.LogicalLocations[0]
		result.LogicalLocation = &ris.LogicalLocation{
			Name:               logLoc.Name,
			FullyQualifiedName: logLoc.FullyQualifiedName,
			Kind:               logLoc.Kind,
		}
	}

	return result
}

// buildTitle builds a finding title from result and rule.
func (p *Parser) buildTitle(result *Result, rule *Rule) string {
	if rule != nil && rule.ShortDescription != nil && rule.ShortDescription.Text != "" {
		return rule.ShortDescription.Text
	}

	if rule != nil && rule.Name != "" {
		return rule.Name
	}

	// Extract from rule ID (e.g., "go/sql-injection" -> "SQL Injection")
	parts := strings.Split(result.RuleID, "/")
	if len(parts) > 1 {
		return slugToTitle(parts[len(parts)-1])
	}

	return result.RuleID
}

// convertLevel converts SARIF level to RIS severity.
func (p *Parser) convertLevel(level string, rule *Rule) ris.Severity {
	// Try security-severity first (CVSS-like score)
	if rule != nil && rule.Properties.SecuritySeverity != "" {
		score, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64)
		if err == nil {
			switch {
			case score >= 9.0:
				return ris.SeverityCritical
			case score >= 7.0:
				return ris.SeverityHigh
			case score >= 4.0:
				return ris.SeverityMedium
			case score >= 0.1:
				return ris.SeverityLow
			default:
				return ris.SeverityInfo
			}
		}
	}

	// Fall back to level
	switch strings.ToLower(level) {
	case "error":
		return ris.SeverityHigh
	case "warning":
		return ris.SeverityMedium
	case "note":
		return ris.SeverityLow
	default:
		return ris.SeverityInfo
	}
}

// getConfidence returns confidence score based on rule precision.
func (p *Parser) getConfidence(rule *Rule) int {
	if rule == nil {
		return 50
	}

	switch rule.Properties.Precision {
	case "very-high":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 40
	default:
		return 50
	}
}

// normalizeCWEs normalizes CWE identifiers.
func (p *Parser) normalizeCWEs(cwes []string) []string {
	result := make([]string, 0, len(cwes))
	for _, cwe := range cwes {
		// Ensure format is "CWE-XXX"
		cwe = strings.TrimSpace(cwe)
		if !strings.HasPrefix(cwe, "CWE-") {
			cwe = "CWE-" + strings.TrimPrefix(cwe, "cwe-")
		}
		result = append(result, cwe)
	}
	return result
}

// extractReferences extracts URLs from markdown text.
func (p *Parser) extractReferences(markdown string) []string {
	if markdown == "" {
		return nil
	}

	// Match markdown links: [text](url)
	re := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	matches := re.FindAllStringSubmatch(markdown, -1)

	refs := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 3 {
			refs = append(refs, match[2])
		}
	}

	return refs
}

// getToolVersion extracts CodeQL version from SARIF.
func (p *Parser) getToolVersion(data []byte) string {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return ""
	}

	if len(report.Runs) > 0 {
		return report.Runs[0].Tool.Driver.Version
	}

	return ""
}

// buildDataFlowSummary creates a human-readable summary of the dataflow.
func (p *Parser) buildDataFlowSummary(df *ris.DataFlow) string {
	if len(df.Sources) == 0 || len(df.Sinks) == 0 {
		return ""
	}

	source := df.Sources[0]
	sink := df.Sinks[len(df.Sinks)-1]

	summary := "Tainted data"
	if source.Label != "" {
		summary = source.Label
	}

	summary += " flows from "
	if source.Path != "" {
		summary += source.Path
		if source.Line > 0 {
			summary += fmt.Sprintf(":%d", source.Line)
		}
	}

	if len(df.Intermediates) > 0 {
		summary += fmt.Sprintf(" through %d step(s)", len(df.Intermediates))
	}

	summary += " to "
	if sink.Function != "" {
		summary += sink.Function + "()"
	} else if sink.Path != "" {
		summary += sink.Path
		if sink.Line > 0 {
			summary += fmt.Sprintf(":%d", sink.Line)
		}
	} else {
		summary += "sink"
	}

	return summary
}

// slugToTitle converts a slug to title case.
func slugToTitle(slug string) string {
	// Replace hyphens and underscores with spaces
	s := strings.ReplaceAll(slug, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")

	// Title case
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// =============================================================================
// Convenience Functions
// =============================================================================

// ParseSARIF parses CodeQL SARIF data to RIS findings.
func ParseSARIF(data []byte) ([]*ris.Finding, error) {
	return NewParser().Parse(data)
}

// ParseSARIFFile parses a CodeQL SARIF file to RIS findings.
func ParseSARIFFile(path string) ([]*ris.Finding, error) {
	data, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	content, err := readFile(data)
	if err != nil {
		return nil, err
	}

	return ParseSARIF(content)
}

// readFile reads a file and returns its contents.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
