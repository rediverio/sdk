package gitleaks

import (
	"context"
	"fmt"
	"time"

	"github.com/rediverio/rediver-sdk/pkg/core"
	"github.com/rediverio/rediver-sdk/pkg/ris"
)

// Parser converts gitleaks output to RIS format.
type Parser struct{}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "gitleaks"
}

// SupportedFormats returns the output formats this parser can handle.
func (p *Parser) SupportedFormats() []string {
	return []string{"json"}
}

// CanParse checks if the parser can handle the given data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as gitleaks JSON
	_, err := ParseJSONBytes(data)
	return err == nil
}

// Parse converts gitleaks JSON output to RIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ris.Report, error) {
	// Parse gitleaks findings
	findings, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	// Create RIS report
	report := ris.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &ris.Tool{
		Name:   "gitleaks",
		Vendor: "Gitleaks",
		Capabilities: []string{
			"secret_detection",
			"api_key_detection",
			"password_detection",
			"private_key_detection",
			"git_history_scan",
		},
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
	for i, f := range findings {
		risFinding := p.convertFinding(f, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	return report, nil
}

// convertFinding converts a gitleaks finding to RIS finding.
func (p *Parser) convertFinding(f Finding, index int, opts *core.ParseOptions) ris.Finding {
	finding := ris.Finding{
		ID:         fmt.Sprintf("finding-%d", index+1),
		Type:       ris.FindingTypeSecret,
		Title:      fmt.Sprintf("%s detected in %s:%d", f.Description, f.File, f.StartLine),
		Severity:   ris.SeverityHigh, // Secrets are always high severity
		Confidence: 90,
		Category:   "Hardcoded Secret",
		RuleID:     f.RuleID,
		RuleName:   f.Description,
	}

	// Generate or use fingerprint
	if f.Fingerprint != "" {
		finding.Fingerprint = f.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSecretFingerprint(f.File, f.RuleID, f.StartLine, f.Secret)
	}

	// Set location
	finding.Location = &ris.FindingLocation{
		Path:        f.File,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Snippet:     f.Match,
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

	// If commit from gitleaks is available, use it
	if f.Commit != "" {
		finding.Location.CommitSHA = f.Commit
	}

	// Set secret details
	finding.Secret = &ris.SecretDetails{
		SecretType:  GetSecretType(f.RuleID),
		Service:     GetServiceName(f.RuleID),
		MaskedValue: core.MaskSecret(f.Secret),
		Length:      len(f.Secret),
		Entropy:     f.Entropy,
	}

	// Link to asset
	if opts != nil && opts.AssetValue != "" {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		finding.AssetRef = assetID
	}

	// Add default confidence
	if opts != nil && opts.DefaultConfidence > 0 {
		finding.Confidence = opts.DefaultConfidence
	}

	// Add remediation guidance
	finding.Remediation = &ris.Remediation{
		Recommendation: fmt.Sprintf("Remove the %s from the codebase and rotate/revoke it immediately.", GetSecretType(f.RuleID)),
		Steps: []string{
			"1. Revoke the exposed secret immediately",
			"2. Generate a new secret/credential",
			"3. Update the secret in a secure vault (e.g., HashiCorp Vault, AWS Secrets Manager)",
			"4. Remove the secret from the codebase and git history if necessary",
			"5. Add the file pattern to .gitignore to prevent future commits",
		},
		Effort:       "low",
		FixAvailable: true,
	}

	// Add references
	finding.References = []string{
		"https://github.com/gitleaks/gitleaks",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
	}

	// Add tags
	finding.Tags = []string{
		"secret",
		GetSecretType(f.RuleID),
		GetServiceName(f.RuleID),
	}

	return finding
}

// ParseToRIS is a convenience function to parse gitleaks JSON to RIS.
func ParseToRIS(data []byte, opts *core.ParseOptions) (*ris.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}
