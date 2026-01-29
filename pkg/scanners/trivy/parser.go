package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/exploopio/sdk/pkg/core"
	"github.com/exploopio/sdk/pkg/eis"
)

// Parser converts Trivy JSON output to EIS format.
type Parser struct {
	// Configuration
	Verbose bool
}

// NewParser creates a new Trivy parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "trivy"
}

// SupportedFormats returns supported output formats.
func (p *Parser) SupportedFormats() []string {
	return []string{"json", "trivy"}
}

// CanParse checks if this parser can handle the data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as Trivy JSON
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return false
	}

	// Check for Trivy-specific fields
	return report.SchemaVersion > 0 || report.ArtifactType != "" || len(report.Results) > 0
}

// Parse converts Trivy JSON output to EIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*eis.Report, error) {
	var trivyReport Report
	if err := json.Unmarshal(data, &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Create EIS report
	report := eis.NewReport()

	// Set metadata
	report.Metadata = eis.ReportMetadata{
		ID:         fmt.Sprintf("trivy-%d", time.Now().Unix()),
		Timestamp:  time.Now(),
		SourceType: "scanner",
	}

	// Set tool info
	report.Tool = &eis.Tool{
		Name:         "trivy",
		Vendor:       "Aqua Security",
		Capabilities: p.inferCapabilities(&trivyReport),
	}

	// Create asset from options, branch info, or artifact
	if asset := p.createAssetFromContext(&trivyReport, opts); asset != nil {
		report.Assets = append(report.Assets, *asset)
	}

	// Parse results
	for _, result := range trivyReport.Results {
		// Parse vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := p.parseVulnerability(&result, &vuln, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse misconfigurations
		for _, misconfig := range result.Misconfigurations {
			finding := p.parseMisconfiguration(&result, &misconfig, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse secrets
		for _, secret := range result.Secrets {
			finding := p.parseSecret(&result, &secret, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse packages (SBOM)
		for _, pkg := range result.Packages {
			dep := p.parsePackage(&result, &pkg, opts)
			report.Dependencies = append(report.Dependencies, dep)
		}
	}

	if p.Verbose {
		fmt.Printf("[trivy-parser] Parsed %d findings from %s\n", len(report.Findings), trivyReport.ArtifactName)
	}

	return report, nil
}

// createAssetFromContext creates an asset from options, branch info, or Trivy artifact.
// Priority: opts.AssetValue > opts.BranchInfo.RepositoryURL > ArtifactName
func (p *Parser) createAssetFromContext(report *Report, opts *core.ParseOptions) *eis.Asset {
	assetID := "asset-1"
	if opts != nil && opts.AssetID != "" {
		assetID = opts.AssetID
	}

	// Priority 1: Explicit AssetValue from options
	if opts != nil && opts.AssetValue != "" {
		assetType := opts.AssetType
		if assetType == "" {
			assetType = eis.AssetTypeRepository
		}
		asset := &eis.Asset{
			ID:          assetID,
			Type:        assetType,
			Value:       opts.AssetValue,
			Name:        opts.AssetValue,
			Criticality: eis.CriticalityHigh,
			Properties: eis.Properties{
				"source": "parse_options",
			},
		}
		// Add OS metadata if available
		if report.Metadata.OS != nil {
			asset.Tags = append(asset.Tags, report.Metadata.OS.Family)
		}
		return asset
	}

	// Priority 2: BranchInfo.RepositoryURL
	if opts != nil && opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
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

		asset := &eis.Asset{
			ID:          assetID,
			Type:        eis.AssetTypeRepository,
			Value:       opts.BranchInfo.RepositoryURL,
			Name:        opts.BranchInfo.RepositoryURL,
			Criticality: eis.CriticalityHigh,
			Properties:  props,
		}
		// Add OS metadata if available
		if report.Metadata.OS != nil {
			asset.Tags = append(asset.Tags, report.Metadata.OS.Family)
		}
		return asset
	}

	// Priority 3: Trivy ArtifactName (existing behavior)
	if report.ArtifactName != "" {
		return p.parseArtifactAsAsset(report, opts)
	}

	return nil
}

// parseArtifactAsAsset converts Trivy artifact to EIS asset.
func (p *Parser) parseArtifactAsAsset(report *Report, opts *core.ParseOptions) *eis.Asset {
	if report.ArtifactName == "" {
		return nil
	}

	assetType := eis.AssetTypeRepository
	switch report.ArtifactType {
	case "container_image":
		assetType = eis.AssetTypeContainer
	case "filesystem":
		assetType = eis.AssetTypeRepository
	case "repository":
		assetType = eis.AssetTypeRepository
	}

	// Override with options if provided
	if opts != nil && opts.AssetType != "" {
		assetType = opts.AssetType
	}

	asset := &eis.Asset{
		ID:    fmt.Sprintf("asset-%x", sha256.Sum256([]byte(report.ArtifactName)))[:16],
		Type:  assetType,
		Value: report.ArtifactName,
		Name:  report.ArtifactName,
	}

	// Add metadata
	if report.Metadata.OS != nil {
		asset.Tags = append(asset.Tags, report.Metadata.OS.Family)
	}

	return asset
}

// parseVulnerability converts Trivy vulnerability to EIS finding.
func (p *Parser) parseVulnerability(result *Result, vuln *Vulnerability, opts *core.ParseOptions) eis.Finding {
	// Get CVSS info
	cvssScore, cvssVector, cvssSource := GetBestCVSSScore(vuln.CVSS)

	// Generate fingerprint
	fingerprint := p.generateFingerprint(vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, result.Target)

	finding := eis.Finding{
		ID:          vuln.VulnerabilityID,
		Type:        eis.FindingTypeVulnerability,
		Title:       p.buildVulnTitle(vuln),
		Description: vuln.Description,
		Severity:    eis.Severity(GetRISSeverity(vuln.Severity)),
		Confidence:  100, // Trivy is deterministic
		RuleID:      vuln.VulnerabilityID,
		RuleName:    vuln.Title,
		Category:    "vulnerability",
		Fingerprint: fingerprint,
	}

	// Set location
	if vuln.PkgPath != "" {
		finding.Location = &eis.FindingLocation{
			Path: vuln.PkgPath,
		}
	} else if result.Target != "" {
		finding.Location = &eis.FindingLocation{
			Path: result.Target,
		}
	}

	// Set vulnerability details
	finding.Vulnerability = &eis.VulnerabilityDetails{
		CVEID:           vuln.VulnerabilityID,
		CWEIDs:          vuln.CweIDs,
		CVSSVersion:     p.getCVSSVersion(cvssVector),
		CVSSScore:       cvssScore,
		CVSSVector:      cvssVector,
		CVSSSource:      cvssSource,
		Package:         vuln.PkgName,
		AffectedVersion: vuln.InstalledVersion,
		FixedVersion:    vuln.FixedVersion,
		Ecosystem:       result.Type,
		PURL:            buildPURL(result.Type, vuln.PkgName, vuln.InstalledVersion),
	}

	// Set references
	if vuln.PrimaryURL != "" {
		finding.References = append(finding.References, vuln.PrimaryURL)
	}
	finding.References = append(finding.References, vuln.References...)

	// Set remediation
	if vuln.FixedVersion != "" {
		finding.Remediation = &eis.Remediation{
			Recommendation: fmt.Sprintf("Upgrade %s from %s to %s", vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion),
			FixAvailable:   true,
		}
	}

	// Set tags
	finding.Tags = []string{"sca", result.Type}
	if vuln.Status != "" {
		finding.Tags = append(finding.Tags, vuln.Status)
	}

	// Link to asset
	if p.hasAssetInfo(opts) {
		finding.AssetRef = p.getAssetID(opts)
	}

	return finding
}

// parseMisconfiguration converts Trivy misconfiguration to EIS finding.
func (p *Parser) parseMisconfiguration(result *Result, misconfig *Misconfiguration, opts *core.ParseOptions) eis.Finding {
	// Skip PASS status
	if misconfig.Status == "PASS" {
		return eis.Finding{}
	}

	fingerprint := p.generateFingerprint(misconfig.ID, result.Target, misconfig.Type, misconfig.Message)

	finding := eis.Finding{
		ID:          misconfig.ID,
		Type:        eis.FindingTypeMisconfiguration,
		Title:       misconfig.Title,
		Description: misconfig.Description,
		Severity:    eis.Severity(GetRISSeverity(misconfig.Severity)),
		Confidence:  100,
		RuleID:      misconfig.ID,
		RuleName:    misconfig.Title,
		Category:    "misconfiguration",
		Fingerprint: fingerprint,
	}

	// Set location
	if misconfig.CauseMetadata.StartLine > 0 {
		finding.Location = &eis.FindingLocation{
			Path:      result.Target,
			StartLine: misconfig.CauseMetadata.StartLine,
			EndLine:   misconfig.CauseMetadata.EndLine,
		}

		// Add code snippet
		if len(misconfig.CauseMetadata.Code.Lines) > 0 {
			var snippet strings.Builder
			for _, line := range misconfig.CauseMetadata.Code.Lines {
				if line.IsCause {
					snippet.WriteString(line.Content)
					snippet.WriteString("\n")
				}
			}
			finding.Location.Snippet = strings.TrimSuffix(snippet.String(), "\n")
		}
	} else {
		finding.Location = &eis.FindingLocation{
			Path: result.Target,
		}
	}

	// Set misconfiguration details
	finding.Misconfiguration = &eis.MisconfigurationDetails{
		PolicyID:     misconfig.ID,
		PolicyName:   misconfig.Title,
		ResourceType: misconfig.Type,
		ResourceName: misconfig.CauseMetadata.Resource,
		Cause:        misconfig.Message,
	}

	// Set references
	if misconfig.PrimaryURL != "" {
		finding.References = append(finding.References, misconfig.PrimaryURL)
	}
	finding.References = append(finding.References, misconfig.References...)

	// Set remediation
	if misconfig.Resolution != "" {
		finding.Remediation = &eis.Remediation{
			Recommendation: misconfig.Resolution,
		}
	}

	// Append message to description if both exist and are different
	// Message contains the specific cause, while Description contains general explanation
	if misconfig.Message != "" && misconfig.Message != misconfig.Description {
		if finding.Description != "" {
			finding.Description = finding.Description + "\n\nCause: " + misconfig.Message
		} else {
			finding.Description = misconfig.Message
		}
	}

	// Set tags
	finding.Tags = []string{"iac", misconfig.Type}
	if misconfig.CauseMetadata.Provider != "" {
		finding.Tags = append(finding.Tags, misconfig.CauseMetadata.Provider)
	}

	// Link to asset
	if p.hasAssetInfo(opts) {
		finding.AssetRef = p.getAssetID(opts)
	}

	return finding
}

// parseSecret converts Trivy secret to EIS finding.
func (p *Parser) parseSecret(result *Result, secret *Secret, opts *core.ParseOptions) eis.Finding {
	fingerprint := p.generateFingerprint(secret.RuleID, result.Target, fmt.Sprintf("%d", secret.StartLine), secret.Match)

	finding := eis.Finding{
		ID:          fmt.Sprintf("%s-%d", secret.RuleID, secret.StartLine),
		Type:        eis.FindingTypeSecret,
		Title:       secret.Title,
		Description: fmt.Sprintf("Secret detected: %s", secret.Category),
		Severity:    eis.Severity(GetRISSeverity(secret.Severity)),
		Confidence:  100,
		RuleID:      secret.RuleID,
		RuleName:    secret.Title,
		Category:    "secret",
		Fingerprint: fingerprint,
	}

	// Set location
	finding.Location = &eis.FindingLocation{
		Path:      result.Target,
		StartLine: secret.StartLine,
		EndLine:   secret.EndLine,
	}

	// Add code snippet
	if len(secret.Code.Lines) > 0 {
		var snippet strings.Builder
		for _, line := range secret.Code.Lines {
			snippet.WriteString(line.Content)
			snippet.WriteString("\n")
		}
		finding.Location.Snippet = strings.TrimSuffix(snippet.String(), "\n")
	}

	// Set secret details
	finding.Secret = &eis.SecretDetails{
		SecretType:  secret.Category,
		MaskedValue: maskSecret(secret.Match),
		Length:      len(secret.Match),
	}

	// Set tags
	finding.Tags = []string{"secret", secret.Category}

	// Link to asset
	if p.hasAssetInfo(opts) {
		finding.AssetRef = p.getAssetID(opts)
	}

	return finding
}

// parsePackage converts Trivy package to EIS dependency.
func (p *Parser) parsePackage(result *Result, pkg *Package, opts *core.ParseOptions) eis.Dependency {
	id := p.generateFingerprint("pkg", result.Target, pkg.Name, pkg.Version)

	dep := eis.Dependency{
		ID:           id,
		Name:         pkg.Name,
		Version:      pkg.Version,
		PURL:         pkg.Identifier.PURL,
		Licenses:     pkg.Licenses,
		Relationship: pkg.Relationship,
		DependsOn:    pkg.DependsOn,
	}

	// Determine ecosystem
	if pkg.Identifier.PURL != "" {
		// pkg:golang/github.com/foo/bar -> golang
		if parts := strings.Split(pkg.Identifier.PURL, "/"); len(parts) > 0 {
			if typeParams := strings.Split(parts[0], ":"); len(typeParams) > 1 {
				dep.Ecosystem = typeParams[1]
			}
		}
	}
	if dep.Ecosystem == "" {
		dep.Ecosystem = result.Type
	}

	// Set location
	dep.Location = &eis.FindingLocation{
		Path: result.Target,
	}
	if pkg.FilePath != "" {
		dep.Location.Path = pkg.FilePath
	} else if pkg.PkgPath != "" {
		dep.Location.Path = pkg.PkgPath
	}

	return dep
}

// buildVulnTitle builds a title for vulnerability.
func (p *Parser) buildVulnTitle(vuln *Vulnerability) string {
	if vuln.Title != "" {
		return fmt.Sprintf("%s: %s", vuln.VulnerabilityID, vuln.Title)
	}
	return fmt.Sprintf("%s in %s %s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
}

// generateFingerprint generates a unique fingerprint.
func (p *Parser) generateFingerprint(parts ...string) string {
	data := strings.Join(parts, ":")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

// getCVSSVersion extracts CVSS version from vector.
func (p *Parser) getCVSSVersion(vector string) string {
	if strings.HasPrefix(vector, "CVSS:3.1") {
		return "3.1"
	}
	if strings.HasPrefix(vector, "CVSS:3.0") {
		return "3.0"
	}
	if strings.Contains(vector, "AV:") && !strings.HasPrefix(vector, "CVSS:") {
		return "2.0"
	}
	return ""
}

// getAssetID returns the asset ID from options or a default.
func (p *Parser) getAssetID(opts *core.ParseOptions) string {
	if opts != nil && opts.AssetID != "" {
		return opts.AssetID
	}
	return "asset-1"
}

// hasAssetInfo checks if we have any asset information in options.
func (p *Parser) hasAssetInfo(opts *core.ParseOptions) bool {
	if opts == nil {
		return false
	}
	if opts.AssetValue != "" {
		return true
	}
	if opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
		return true
	}
	return false
}

// inferCapabilities infers tool capabilities from report.
func (p *Parser) inferCapabilities(report *Report) []string {
	caps := make(map[string]bool)

	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			caps["vulnerability"] = true
			caps["sca"] = true
		}
		if len(result.Misconfigurations) > 0 {
			caps["misconfiguration"] = true
			caps["iac"] = true
		}
		if len(result.Secrets) > 0 {
			caps["secret_detection"] = true
		}
		if len(result.Licenses) > 0 {
			caps["license_compliance"] = true
		}
	}

	result := make([]string, 0, len(caps))
	for cap := range caps {
		result = append(result, cap)
	}
	return result
}

// maskSecret masks a secret value.
func maskSecret(value string) string {
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// ParseJSONBytes parses Trivy JSON output from bytes.
func ParseJSONBytes(data []byte) (*Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON: %w", err)
	}
	return &report, nil
}
