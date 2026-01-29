// Package sarif provides an adapter to convert SARIF format to RIS.
package sarif

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rediverio/sdk/pkg/core"
	"github.com/rediverio/sdk/pkg/ris"
)

// Adapter converts SARIF (Static Analysis Results Interchange Format) to RIS.
type Adapter struct{}

// NewAdapter creates a new SARIF adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "sarif"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"sarif", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ris"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var sarif SARIFReport
	if err := json.Unmarshal(input, &sarif); err != nil {
		return false
	}
	// Check for SARIF schema
	return sarif.Schema != "" || sarif.Version != ""
}

// Convert transforms SARIF input to RIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ris.Report, error) {
	var sarif SARIFReport
	if err := json.Unmarshal(input, &sarif); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}

	report := ris.NewReport()
	report.Metadata.SourceType = "scanner"

	if opts != nil {
		report.Metadata.Scope = &ris.Scope{
			Name: opts.Repository,
		}
	}

	// Process each run
	for _, run := range sarif.Runs {
		// Set tool info from first run
		if report.Tool == nil && run.Tool.Driver.Name != "" {
			report.Tool = &ris.Tool{
				Name:    run.Tool.Driver.Name,
				Version: run.Tool.Driver.Version,
				Vendor:  run.Tool.Driver.Organization,
			}
		}

		// Build rule index for quick lookup
		ruleIndex := make(map[string]*SARIFRule)
		for i := range run.Tool.Driver.Rules {
			rule := &run.Tool.Driver.Rules[i]
			ruleIndex[rule.ID] = rule
		}

		// Convert results to findings
		for _, result := range run.Results {
			finding := a.convertResult(result, ruleIndex, opts)
			if finding != nil {
				report.Findings = append(report.Findings, *finding)
			}
		}
	}

	return report, nil
}

// convertResult converts a SARIF result to a RIS finding.
func (a *Adapter) convertResult(result SARIFResult, ruleIndex map[string]*SARIFRule, opts *core.AdapterOptions) *ris.Finding {
	rule := ruleIndex[result.RuleID]

	finding := &ris.Finding{
		ID:       result.RuleID,
		Type:     ris.FindingTypeVulnerability,
		RuleID:   result.RuleID,
		Severity: mapSARIFSeverity(result.Level),
	}

	// Get info from rule if available
	if rule != nil {
		finding.Title = rule.ShortDescription.Text
		if finding.Title == "" {
			finding.Title = rule.Name
		}
		finding.Description = rule.FullDescription.Text
		finding.RuleName = rule.Name

		// Extract CWE if available
		for _, tag := range rule.Properties.Tags {
			if len(tag) > 4 && tag[:4] == "CWE-" {
				if finding.Vulnerability == nil {
					finding.Vulnerability = &ris.VulnerabilityDetails{}
				}
				finding.Vulnerability.CWEIDs = append(finding.Vulnerability.CWEIDs, tag)
			}
		}

		// Add help URL as reference
		if rule.HelpURI != "" {
			finding.References = append(finding.References, rule.HelpURI)
		}
	}

	// Use message as title fallback
	if finding.Title == "" {
		finding.Title = result.Message.Text
	}

	// Set location from first location
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		finding.Location = &ris.FindingLocation{
			Path:        loc.PhysicalLocation.ArtifactLocation.URI,
			StartLine:   loc.PhysicalLocation.Region.StartLine,
			EndLine:     loc.PhysicalLocation.Region.EndLine,
			StartColumn: loc.PhysicalLocation.Region.StartColumn,
			EndColumn:   loc.PhysicalLocation.Region.EndColumn,
			Snippet:     loc.PhysicalLocation.Region.Snippet.Text,
		}
	}

	// Convert code flows (taint tracking)
	if len(result.CodeFlows) > 0 {
		finding.DataFlow = a.convertCodeFlow(result.CodeFlows[0])
	}

	// Map SARIF 2.1.0 extended fields
	finding.Kind = result.Kind
	finding.BaselineState = result.BaselineState
	finding.Rank = result.Rank
	finding.OccurrenceCount = result.OccurrenceCount
	finding.CorrelationID = result.CorrelationGuid
	finding.PartialFingerprints = result.PartialFingerprints
	finding.WorkItemURIs = result.WorkItemUris
	finding.HostedViewerURI = result.HostedViewerUri

	// Convert related locations
	for _, loc := range result.RelatedLocations {
		finding.RelatedLocations = append(finding.RelatedLocations, &ris.FindingLocation{
			Path:        loc.PhysicalLocation.ArtifactLocation.URI,
			StartLine:   loc.PhysicalLocation.Region.StartLine,
			EndLine:     loc.PhysicalLocation.Region.EndLine,
			StartColumn: loc.PhysicalLocation.Region.StartColumn,
			EndColumn:   loc.PhysicalLocation.Region.EndColumn,
			Snippet:     loc.PhysicalLocation.Region.Snippet.Text,
		})
	}

	// Convert stacks
	for _, stack := range result.Stacks {
		st := &ris.StackTrace{
			Message: stack.Message.Text,
		}
		for _, frame := range stack.Frames {
			st.Frames = append(st.Frames, &ris.StackFrame{
				Location: &ris.FindingLocation{
					Path:        frame.Location.PhysicalLocation.ArtifactLocation.URI,
					StartLine:   frame.Location.PhysicalLocation.Region.StartLine,
					EndLine:     frame.Location.PhysicalLocation.Region.EndLine,
					StartColumn: frame.Location.PhysicalLocation.Region.StartColumn,
					EndColumn:   frame.Location.PhysicalLocation.Region.EndColumn,
					Snippet:     frame.Location.PhysicalLocation.Region.Snippet.Text,
				},
				Module:     frame.Module,
				ThreadID:   frame.ThreadId,
				Parameters: frame.Parameters,
			})
		}
		finding.Stacks = append(finding.Stacks, st)
	}

	// Convert attachments
	for _, att := range result.Attachments {
		finding.Attachments = append(finding.Attachments, &ris.Attachment{
			Description: att.Description.Text,
			ArtifactLocation: &ris.ArtifactLocation{
				URI: att.ArtifactLocation.URI,
			},
		})
	}

	// Filter by severity if option is set
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ris.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// convertCodeFlow converts SARIF code flow to RIS data flow.
func (a *Adapter) convertCodeFlow(cf SARIFCodeFlow) *ris.DataFlow {
	if len(cf.ThreadFlows) == 0 {
		return nil
	}

	dataFlow := &ris.DataFlow{}

	for _, tf := range cf.ThreadFlows {
		for i, loc := range tf.Locations {
			dfLoc := ris.DataFlowLocation{
				Path:    loc.Location.PhysicalLocation.ArtifactLocation.URI,
				Line:    loc.Location.PhysicalLocation.Region.StartLine,
				Column:  loc.Location.PhysicalLocation.Region.StartColumn,
				Content: loc.Location.PhysicalLocation.Region.Snippet.Text,
				Index:   i,
			}

			// First location is source, last is sink, rest are intermediates
			if i == 0 {
				dataFlow.Sources = append(dataFlow.Sources, dfLoc)
			} else if i == len(tf.Locations)-1 {
				dataFlow.Sinks = append(dataFlow.Sinks, dfLoc)
			} else {
				dataFlow.Intermediates = append(dataFlow.Intermediates, dfLoc)
			}
		}
	}

	return dataFlow
}

// mapSARIFSeverity maps SARIF level to RIS severity.
func mapSARIFSeverity(level string) ris.Severity {
	switch level {
	case "error":
		return ris.SeverityHigh
	case "warning":
		return ris.SeverityMedium
	case "note":
		return ris.SeverityLow
	case "none":
		return ris.SeverityInfo
	default:
		return ris.SeverityMedium
	}
}

// meetsMinSeverity checks if severity meets minimum threshold.
func meetsMinSeverity(s, min ris.Severity) bool {
	order := map[ris.Severity]int{
		ris.SeverityCritical: 5,
		ris.SeverityHigh:     4,
		ris.SeverityMedium:   3,
		ris.SeverityLow:      2,
		ris.SeverityInfo:     1,
	}
	return order[s] >= order[min]
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// =============================================================================
// SARIF Types
// =============================================================================

// SARIFReport is the root SARIF document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver.
type SARIFDriver struct {
	Name         string      `json:"name"`
	Version      string      `json:"version"`
	Organization string      `json:"organization"`
	Rules        []SARIFRule `json:"rules"`
}

// SARIFRule describes a detection rule.
type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	FullDescription  SARIFMessage   `json:"fullDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       SARIFRuleProps `json:"properties"`
}

// SARIFRuleProps contains rule properties.
type SARIFRuleProps struct {
	Tags []string `json:"tags"`
}

// SARIFMessage is a SARIF message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	CodeFlows []SARIFCodeFlow `json:"codeFlows"`

	// SARIF 2.1.0 extended fields
	Kind                string            `json:"kind,omitempty"`                // not_applicable, pass, fail, review, open, informational
	BaselineState       string            `json:"baselineState,omitempty"`       // new, unchanged, updated, absent
	Rank                float64           `json:"rank,omitempty"`                // 0-100 priority score
	OccurrenceCount     int               `json:"occurrenceCount,omitempty"`     // Number of times observed
	CorrelationGuid     string            `json:"correlationGuid,omitempty"`     // Groups logically identical results
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"` // Contributing identity components
	RelatedLocations    []SARIFLocation   `json:"relatedLocations,omitempty"`    // Additional related locations
	Stacks              []SARIFStack      `json:"stacks,omitempty"`              // Call stacks
	Attachments         []SARIFAttachment `json:"attachments,omitempty"`         // Artifacts or evidence
	WorkItemUris        []string          `json:"workItemUris,omitempty"`        // Associated issues/tickets
	HostedViewerUri     string            `json:"hostedViewerUri,omitempty"`     // URI to view in hosted viewer
}

// SARIFLocation is a location in a result.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a physical file location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation is an artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a region within a file.
type SARIFRegion struct {
	StartLine   int          `json:"startLine"`
	EndLine     int          `json:"endLine"`
	StartColumn int          `json:"startColumn"`
	EndColumn   int          `json:"endColumn"`
	Snippet     SARIFSnippet `json:"snippet"`
}

// SARIFSnippet is a code snippet.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFCodeFlow represents a code flow (taint tracking).
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

// SARIFThreadFlow is a thread flow in a code flow.
type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

// SARIFThreadFlowLocation is a location in a thread flow.
type SARIFThreadFlowLocation struct {
	Location     SARIFLocation `json:"location"`
	NestingLevel int           `json:"nestingLevel,omitempty"`
	Importance   string        `json:"importance,omitempty"` // essential, important, unimportant
}

// SARIFStack represents a call stack.
type SARIFStack struct {
	Message SARIFMessage      `json:"message,omitempty"`
	Frames  []SARIFStackFrame `json:"frames"`
}

// SARIFStackFrame is a single frame in a call stack.
type SARIFStackFrame struct {
	Location   SARIFLocation `json:"location,omitempty"`
	Module     string        `json:"module,omitempty"`
	ThreadId   int           `json:"threadId,omitempty"`
	Parameters []string      `json:"parameters,omitempty"`
}

// SARIFAttachment represents an artifact or evidence attachment.
type SARIFAttachment struct {
	Description      SARIFMessage          `json:"description,omitempty"`
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation,omitempty"`
}
