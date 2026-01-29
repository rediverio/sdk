package semgrep

import (
	"context"
	"fmt"
	"time"

	"github.com/exploopio/sdk/pkg/core"
	"github.com/exploopio/sdk/pkg/eis"
)

// Parser converts semgrep output to EIS format.
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

// Parse converts semgrep JSON output to EIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*eis.Report, error) {
	// Parse semgrep report
	semgrepReport, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Create EIS report
	report := eis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &eis.Tool{
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

	// Add asset from options or branch info
	if asset := p.createAssetFromOptions(opts); asset != nil {
		report.Assets = append(report.Assets, *asset)
	}

	// Convert findings
	for i, r := range semgrepReport.Results {
		risFinding := p.convertResult(r, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	return report, nil
}

// convertResult converts a semgrep result to EIS finding.
func (p *Parser) convertResult(r Result, index int, opts *core.ParseOptions) eis.Finding {
	finding := eis.Finding{
		ID:                 fmt.Sprintf("finding-%d", index+1),
		Type:               eis.FindingTypeVulnerability,
		Title:              fmt.Sprintf("%s at %s:%d", SlugToNormalText(r.CheckID), r.Path, r.Start.Line),
		Severity:           eis.Severity(r.GetSeverity()),
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
	finding.Location = &eis.FindingLocation{
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
		finding.Vulnerability = &eis.VulnerabilityDetails{
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
		finding.Remediation = &eis.Remediation{
			Recommendation: "Apply the suggested fix",
			FixAvailable:   true,
			AutoFixable:    true,
		}
	}

	// Link to asset (from AssetValue or BranchInfo)
	if opts != nil {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		// Link if we have asset info (either explicit or from branch info)
		if opts.AssetValue != "" || (opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "") {
			finding.AssetRef = assetID
		}
	}

	return finding
}

// convertDataFlow converts semgrep dataflow trace to EIS DataFlow.
func (p *Parser) convertDataFlow(df *DataFlow) *eis.DataFlow {
	result := &eis.DataFlow{}

	// Parse taint source
	if source := ConvertCliLoc(df.TaintSource); source != nil {
		result.Sources = append(result.Sources, eis.DataFlowLocation{
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
		result.Intermediates = append(result.Intermediates, eis.DataFlowLocation{
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
		result.Sinks = append(result.Sinks, eis.DataFlowLocation{
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

// createAssetFromOptions creates an asset from parse options or branch info.
// Priority: opts.AssetValue > opts.BranchInfo.RepositoryURL
func (p *Parser) createAssetFromOptions(opts *core.ParseOptions) *eis.Asset {
	if opts == nil {
		return nil
	}

	assetID := opts.AssetID
	if assetID == "" {
		assetID = "asset-1"
	}

	// Priority 1: Explicit AssetValue
	if opts.AssetValue != "" {
		assetType := opts.AssetType
		if assetType == "" {
			assetType = eis.AssetTypeRepository
		}
		return &eis.Asset{
			ID:          assetID,
			Type:        assetType,
			Value:       opts.AssetValue,
			Name:        opts.AssetValue,
			Criticality: eis.CriticalityHigh,
			Properties: eis.Properties{
				"source": "parse_options",
			},
		}
	}

	// Priority 2: BranchInfo.RepositoryURL
	if opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
		props := eis.Properties{
			"source":       "branch_info",
			"auto_created": true,
		}
		if opts.BranchInfo.CommitSHA != "" {
			props["commit_sha"] = opts.BranchInfo.CommitSHA
		}
		if opts.BranchInfo.Name != "" {
			props["branch"] = opts.BranchInfo.Name
		}
		props["is_default_branch"] = opts.BranchInfo.IsDefaultBranch

		return &eis.Asset{
			ID:          assetID,
			Type:        eis.AssetTypeRepository,
			Value:       opts.BranchInfo.RepositoryURL,
			Name:        opts.BranchInfo.RepositoryURL,
			Criticality: eis.CriticalityHigh,
			Properties:  props,
		}
	}

	return nil
}

// ParseToEIS is a convenience function to parse semgrep JSON to EIS.
func ParseToEIS(data []byte, opts *core.ParseOptions) (*eis.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}
