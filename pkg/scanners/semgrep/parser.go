package semgrep

import (
	"context"
	"fmt"
	"time"

	"github.com/rediverio/sdk/pkg/core"
	"github.com/rediverio/sdk/pkg/ris"
)

// Parser converts semgrep output to RIS format.
type Parser struct{}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "semgrep"
}

// SupportedFormats returns the output formats this parser can handle.
func (p *Parser) SupportedFormats() []string {
	return []string{"json"}
}

// CanParse checks if the parser can handle the given data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as semgrep JSON
	_, err := ParseJSONBytes(data)
	return err == nil
}

// Parse converts semgrep JSON output to RIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ris.Report, error) {
	// Parse semgrep report
	semgrepReport, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Create RIS report
	report := ris.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &ris.Tool{
		Name:   "semgrep",
		Vendor: "Semgrep Inc.",
		Capabilities: []string{
			"sast",
			"code_analysis",
			"vulnerability_detection",
			"code_quality",
			"taint_tracking",
		},
	}
	if semgrepReport.Version != "" {
		report.Tool.Version = semgrepReport.Version
	}

	// Add asset if configured
	if opts != nil && opts.AssetValue != "" {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		report.Assets = append(report.Assets, ris.Asset{
			ID:          assetID,
			Type:        opts.AssetType,
			Value:       opts.AssetValue,
			Criticality: ris.CriticalityHigh,
		})
	}

	// Convert findings
	for i, r := range semgrepReport.Results {
		risFinding := p.convertResult(r, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	return report, nil
}

// convertResult converts a semgrep result to RIS finding.
func (p *Parser) convertResult(r Result, index int, opts *core.ParseOptions) ris.Finding {
	finding := ris.Finding{
		ID:                 fmt.Sprintf("finding-%d", index+1),
		Type:               ris.FindingTypeVulnerability,
		Title:              fmt.Sprintf("%s at %s:%d", SlugToNormalText(r.CheckID), r.Path, r.Start.Line),
		Severity:           ris.Severity(r.GetSeverity()),
		Confidence:         r.GetConfidence(),
		Impact:             r.GetImpact(),
		Likelihood:         r.GetLikelihood(),
		Category:           r.GetCategory(),
		VulnerabilityClass: r.GetVulnerabilityClass(),
		Subcategory:        r.GetSubcategory(),
		RuleID:             r.CheckID,
		RuleName:           SlugToNormalText(r.CheckID),
	}

	// Description
	finding.Description = r.Extra.Message

	// Fingerprint
	if r.Extra.Fingerprint != "" {
		finding.Fingerprint = r.Extra.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSastFingerprint(r.Path, r.CheckID, r.Start.Line)
	}

	// Location
	finding.Location = &ris.FindingLocation{
		Path:        r.Path,
		StartLine:   r.Start.Line,
		EndLine:     r.End.Line,
		StartColumn: r.Start.Col,
		EndColumn:   r.End.Col,
		Snippet:     r.Extra.Lines,
	}

	// Add branch/commit if available
	if opts != nil {
		if opts.Branch != "" {
			finding.Location.Branch = opts.Branch
		}
		if opts.CommitSHA != "" {
			finding.Location.CommitSHA = opts.CommitSHA
		}
	}

	// Vulnerability details (CWE, OWASP, etc.)
	cwes := r.GetCWEs()
	owasps := r.GetOWASPs()
	if len(cwes) > 0 || len(owasps) > 0 {
		finding.Vulnerability = &ris.VulnerabilityDetails{
			CWEIDs:   cwes,
			OWASPIDs: owasps,
		}
		if len(cwes) > 0 {
			finding.Vulnerability.CWEID = cwes[0]
		}
	}

	// Data flow trace
	if r.Extra.DataflowTrace != nil {
		finding.DataFlow = p.convertDataFlow(r.Extra.DataflowTrace)
	}

	// References
	finding.References = r.GetReferences()

	// Tags
	finding.Tags = []string{
		"sast",
		r.GetCategory(),
	}
	if len(r.Extra.Metadata.Technology) > 0 {
		finding.Tags = append(finding.Tags, r.Extra.Metadata.Technology...)
	}

	// Remediation
	if r.Extra.Fix != "" {
		finding.Remediation = &ris.Remediation{
			Recommendation: "Apply the suggested fix",
			FixAvailable:   true,
			AutoFixable:    true,
		}
	}

	// Link to asset
	if opts != nil && opts.AssetValue != "" {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		finding.AssetRef = assetID
	}

	return finding
}

// convertDataFlow converts semgrep dataflow trace to RIS DataFlow.
func (p *Parser) convertDataFlow(df *DataFlow) *ris.DataFlow {
	result := &ris.DataFlow{}

	// Parse taint source
	if source := ConvertCliLoc(df.TaintSource); source != nil {
		result.Sources = append(result.Sources, ris.DataFlowLocation{
			Path:    source.Location.Path,
			Line:    source.Location.Start.Line,
			Column:  source.Location.Start.Col,
			Content: source.Content,
			Label:   "source",
			Index:   0,
		})
	}

	// Parse intermediate vars
	for i, node := range df.IntermediateVars {
		result.Intermediates = append(result.Intermediates, ris.DataFlowLocation{
			Path:    node.Location.Path,
			Line:    node.Location.Start.Line,
			Column:  node.Location.Start.Col,
			Content: node.Content,
			Label:   "intermediate",
			Index:   i + 1,
		})
	}

	// Parse taint sink
	sinks := ConvertCliCall(df.TaintSink)
	if len(sinks) == 0 {
		if sink := ConvertCliLoc(df.TaintSink); sink != nil {
			sinks = append(sinks, sink)
		}
	}
	for i, sink := range sinks {
		result.Sinks = append(result.Sinks, ris.DataFlowLocation{
			Path:    sink.Location.Path,
			Line:    sink.Location.Start.Line,
			Column:  sink.Location.Start.Col,
			Content: sink.Content,
			Label:   "sink",
			Index:   len(df.IntermediateVars) + i + 1,
		})
	}

	return result
}

// ParseToRIS is a convenience function to parse semgrep JSON to RIS.
func ParseToRIS(data []byte, opts *core.ParseOptions) (*ris.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}
