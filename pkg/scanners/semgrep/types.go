// Package semgrep provides a scanner implementation for the Semgrep SAST tool.
package semgrep

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// =============================================================================
// Semgrep JSON Output Types
// =============================================================================

// Report represents the top-level semgrep JSON output.
type Report struct {
	Results []Result `json:"results"`
	Errors  []Error  `json:"errors,omitempty"`
	Paths   Paths    `json:"paths,omitempty"`
	Version string   `json:"version,omitempty"`
}

// Result represents a single semgrep finding.
type Result struct {
	CheckID string  `json:"check_id"`
	Path    string  `json:"path"`
	Start   Region  `json:"start"`
	End     Region  `json:"end"`
	Extra   Extra   `json:"extra"`
}

// Region represents a position in a file.
type Region struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// Extra contains additional finding details.
type Extra struct {
	Fingerprint   string    `json:"fingerprint"`
	Lines         string    `json:"lines"`
	Message       string    `json:"message"`
	Metadata      Metadata  `json:"metadata"`
	Severity      string    `json:"severity"`
	IsIgnored     bool      `json:"is_ignored,omitempty"`
	DataflowTrace *DataFlow `json:"dataflow_trace,omitempty"`
	FixRegex      *FixRegex `json:"fix_regex,omitempty"`
	Fix           string    `json:"fix,omitempty"`
}

// Metadata contains rule metadata.
type Metadata struct {
	// Severity indicators
	Confidence string `json:"confidence,omitempty"`
	Impact     string `json:"impact,omitempty"`
	Likelihood string `json:"likelihood,omitempty"`

	// Classification
	Category           string   `json:"category,omitempty"`
	Subcategory        []string `json:"subcategory,omitempty"`
	VulnerabilityClass []string `json:"vulnerability_class,omitempty"`
	Technology         []string `json:"technology,omitempty"`

	// References
	Source     string   `json:"source,omitempty"`
	SourceURL  string   `json:"source-url,omitempty"`
	References []string `json:"references,omitempty"`

	// CWE/OWASP
	CWE  []string `json:"cwe,omitempty"`
	OWASP []string `json:"owasp,omitempty"`

	// Semgrep specific
	SemgrepDev SemgrepDevMeta `json:"semgrep.dev,omitempty"`

	// Additional metadata
	ShortDescription string `json:"shortDescription,omitempty"`
	Asvs             ASVS   `json:"asvs,omitempty"`
}

// SemgrepDevMeta contains semgrep.dev specific metadata.
type SemgrepDevMeta struct {
	Rule RuleMeta `json:"rule,omitempty"`
}

// RuleMeta contains rule metadata from semgrep.dev.
type RuleMeta struct {
	RuleID    string `json:"rule_id,omitempty"`
	URL       string `json:"url,omitempty"`
	OriginURL string `json:"origin,omitempty"`
}

// ASVS contains ASVS compliance metadata.
type ASVS struct {
	Section string `json:"section,omitempty"`
	Control string `json:"control_id,omitempty"`
	Version string `json:"control_url,omitempty"`
}

// DataFlow represents taint tracking data flow.
type DataFlow struct {
	TaintSource      []interface{} `json:"taint_source,omitempty"`
	IntermediateVars []Node        `json:"intermediate_vars,omitempty"`
	TaintSink        []interface{} `json:"taint_sink,omitempty"`
}

// Node represents a node in the data flow.
type Node struct {
	Content  string   `json:"content"`
	Location Location `json:"location"`
}

// Location represents a code location.
type Location struct {
	Path  string `json:"path"`
	Start Region `json:"start"`
	End   Region `json:"end"`
}

// TaintLocation represents a taint flow location with content.
type TaintLocation struct {
	Location Location `json:"location"`
	Content  string   `json:"content"`
}

// FixRegex contains regex-based fix information.
type FixRegex struct {
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Count       int    `json:"count,omitempty"`
}

// Error represents a semgrep error.
type Error struct {
	Code    int    `json:"code,omitempty"`
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Paths contains scanned and skipped paths.
type Paths struct {
	Scanned []string `json:"scanned,omitempty"`
	Skipped []SkippedPath `json:"skipped,omitempty"`
}

// SkippedPath represents a skipped file/directory.
type SkippedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// =============================================================================
// Parsing Functions
// =============================================================================

// ParseJSON parses semgrep JSON output from a reader.
func ParseJSON(r io.Reader) (*Report, error) {
	var report Report
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON: %w", err)
	}
	return &report, nil
}

// ParseJSONBytes parses semgrep JSON output from bytes.
func ParseJSONBytes(data []byte) (*Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON: %w", err)
	}
	return &report, nil
}

// =============================================================================
// Severity Mapping
// =============================================================================

// Severity constants
const (
	SeverityError   = "ERROR"
	SeverityWarning = "WARNING"
	SeverityInfo    = "INFO"

	ImpactHigh   = "HIGH"
	ImpactMedium = "MEDIUM"
	ImpactLow    = "LOW"
)

// GetSeverity returns the normalized severity for a result.
// Priority: Impact > Severity
func (r *Result) GetSeverity() string {
	// First check impact (more accurate for security findings)
	if r.Extra.Metadata.Impact != "" {
		switch strings.ToUpper(r.Extra.Metadata.Impact) {
		case ImpactHigh:
			return "critical"
		case ImpactMedium:
			return "medium"
		case ImpactLow:
			return "low"
		}
	}

	// Fall back to severity
	switch strings.ToUpper(r.Extra.Severity) {
	case SeverityError:
		return "high"
	case SeverityWarning:
		return "medium"
	case SeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// GetConfidence returns confidence score (0-100).
func (r *Result) GetConfidence() int {
	switch strings.ToUpper(r.Extra.Metadata.Confidence) {
	case "HIGH":
		return 90
	case "MEDIUM":
		return 70
	case "LOW":
		return 50
	default:
		return 70 // Default to medium confidence
	}
}

// =============================================================================
// DataFlow Parsing Helpers
// =============================================================================

// ConvertCliLoc converts a CliLoc node to TaintLocation.
func ConvertCliLoc(node []interface{}) *TaintLocation {
	if len(node) == 2 && reflect.TypeOf(node[0]).Kind() == reflect.String && node[0].(string) == "CliLoc" && reflect.TypeOf(node[1]).Kind() == reflect.Slice {
		locNode := node[1].([]interface{})
		return convertLocNode(locNode)
	}
	return nil
}

// ConvertCliCall converts a CliCall node to TaintLocations.
func ConvertCliCall(node []interface{}) []*TaintLocation {
	var result []*TaintLocation
	if len(node) == 2 && reflect.TypeOf(node[0]).Kind() == reflect.String && node[0].(string) == "CliCall" && reflect.TypeOf(node[1]).Kind() == reflect.Slice {
		callNode := node[1].([]interface{})
		if len(callNode) == 3 {
			if reflect.TypeOf(callNode[0]).Kind() == reflect.Slice {
				taint := convertLocNode(callNode[0].([]interface{}))
				if taint != nil {
					result = append(result, taint)
				}
			}
			if reflect.TypeOf(callNode[1]).Kind() == reflect.Slice {
				for _, taintNode := range callNode[1].([]interface{}) {
					data, _ := json.Marshal(taintNode)
					var taint TaintLocation
					err := json.Unmarshal(data, &taint)
					if err == nil && taint.Location.Path != "" {
						result = append(result, &taint)
					}
				}
			}
			if reflect.TypeOf(callNode[2]).Kind() == reflect.Slice {
				taint := ConvertCliLoc(callNode[2].([]interface{}))
				if taint != nil {
					result = append(result, taint)
				}
			}
		}
	}
	return result
}

func convertLocNode(node []interface{}) *TaintLocation {
	if len(node) == 2 && reflect.TypeOf(node[1]).Kind() == reflect.String {
		data, _ := json.Marshal(node[0])
		var location Location
		err := json.Unmarshal(data, &location)
		if err == nil && location.Path != "" {
			return &TaintLocation{
				Location: location,
				Content:  node[1].(string),
			}
		}
	}
	return nil
}

// =============================================================================
// Utility Functions
// =============================================================================

// SlugToNormalText converts a rule slug to human-readable text.
// Example: "python.django.security.injection.sql-injection" -> "Python Django Security Injection Sql Injection"
func SlugToNormalText(slug string) string {
	parts := strings.Split(slug, ".")
	n := len(parts)
	// Remove duplicate last part
	if n > 1 && parts[n-1] == parts[n-2] {
		parts = parts[:n-1]
	}
	for i, part := range parts {
		subParts := strings.Split(part, "-")
		for j, subPart := range subParts {
			if len(subPart) > 0 {
				subParts[j] = strings.ToUpper(subPart[:1]) + subPart[1:]
			}
		}
		parts[i] = strings.Join(subParts, " ")
	}
	return strings.Join(parts, " ")
}

// GetCategory returns the finding category.
func (r *Result) GetCategory() string {
	if len(r.Extra.Metadata.VulnerabilityClass) > 0 {
		return r.Extra.Metadata.VulnerabilityClass[0]
	}
	if r.Extra.Metadata.Category != "" {
		return r.Extra.Metadata.Category
	}
	return "Security"
}

// GetCWEs returns CWE IDs from metadata.
func (r *Result) GetCWEs() []string {
	return r.Extra.Metadata.CWE
}

// GetReferences returns reference URLs.
func (r *Result) GetReferences() []string {
	refs := make([]string, 0)
	if r.Extra.Metadata.Source != "" {
		refs = append(refs, r.Extra.Metadata.Source)
	}
	if r.Extra.Metadata.SourceURL != "" {
		refs = append(refs, r.Extra.Metadata.SourceURL)
	}
	refs = append(refs, r.Extra.Metadata.References...)
	// Add semgrep.dev rule URL if available
	if r.Extra.Metadata.SemgrepDev.Rule.URL != "" {
		refs = append(refs, r.Extra.Metadata.SemgrepDev.Rule.URL)
	}
	return refs
}
