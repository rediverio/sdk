// Package fingerprint provides unified fingerprint generation algorithms
// for deduplication of security findings across SDK and Backend.
//
// IMPORTANT: This package is shared between rediver-sdk and rediver-api.
// Any changes to fingerprint algorithms must be backward compatible
// or coordinated across both projects.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Type represents the type of finding for fingerprint generation.
type Type string

const (
	// TypeSAST is for Static Application Security Testing findings (code vulnerabilities).
	TypeSAST Type = "sast"

	// TypeSCA is for Software Composition Analysis findings (dependency vulnerabilities).
	TypeSCA Type = "sca"

	// TypeSecret is for secret/credential detection findings.
	TypeSecret Type = "secret"

	// TypeMisconfiguration is for infrastructure/configuration findings.
	TypeMisconfiguration Type = "misconfig"

	// TypeGeneric is for findings that don't fit other categories.
	TypeGeneric Type = "generic"
)

// Input contains the data needed to generate a fingerprint.
// Not all fields are required - only the relevant ones for the finding type.
type Input struct {
	// Type of finding (sast, sca, secret, misconfig, generic)
	Type Type

	// Common fields
	RuleID   string // Rule/check identifier
	FilePath string // File path where finding was detected
	Message  string // Finding message/description

	// Location fields (for SAST, Secret)
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	// SCA-specific fields
	PackageName    string // Package/dependency name
	PackageVersion string // Package version
	VulnerabilityID string // CVE ID or other vuln identifier

	// Secret-specific fields
	SecretValue string // The actual secret (will be hashed)

	// Misconfiguration-specific fields
	ResourceType string // e.g., "aws_s3_bucket", "dockerfile"
	ResourceName string // Resource identifier
}

// Generate creates a fingerprint for the given input.
// The fingerprint is a SHA256 hash (64 hex characters) that uniquely
// identifies a finding based on its type and relevant attributes.
//
// The algorithm varies by finding type to ensure optimal deduplication:
//   - SAST: file + rule + location (same vulnerability in same place)
//   - SCA: package + version + vuln ID (same vuln in same dependency)
//   - Secret: file + rule + location + secret hash (same secret in same place)
//   - Misconfig: resource + rule (same misconfiguration on same resource)
//   - Generic: rule + file + location + message (fallback)
func Generate(input Input) string {
	var data string

	switch input.Type {
	case TypeSAST:
		// SAST: Deduplicate by file location and rule
		// Same vulnerability in the same file/line should be the same finding
		data = fmt.Sprintf("sast:%s:%s:%d:%d",
			normalize(input.FilePath),
			normalize(input.RuleID),
			input.StartLine,
			input.EndLine,
		)

	case TypeSCA:
		// SCA: Deduplicate by package and vulnerability
		// Same CVE in the same package version is the same finding
		data = fmt.Sprintf("sca:%s:%s:%s",
			normalize(input.PackageName),
			normalize(input.PackageVersion),
			normalize(input.VulnerabilityID),
		)

	case TypeSecret:
		// Secret: Include secret hash to distinguish different secrets at same location
		// This handles cases where multiple secrets exist on the same line
		secretHash := ""
		if input.SecretValue != "" {
			secretHash = Hash(input.SecretValue)[:16] // First 16 chars
		}
		data = fmt.Sprintf("secret:%s:%s:%d:%s",
			normalize(input.FilePath),
			normalize(input.RuleID),
			input.StartLine,
			secretHash,
		)

	case TypeMisconfiguration:
		// Misconfig: Deduplicate by resource and rule
		data = fmt.Sprintf("misconfig:%s:%s:%s:%s",
			normalize(input.ResourceType),
			normalize(input.ResourceName),
			normalize(input.RuleID),
			normalize(input.FilePath),
		)

	default:
		// Generic: Use all available location data
		data = fmt.Sprintf("generic:%s:%s:%d:%d:%s",
			normalize(input.RuleID),
			normalize(input.FilePath),
			input.StartLine,
			input.EndLine,
			normalize(input.Message),
		)
	}

	return Hash(data)
}

// GenerateSAST creates a fingerprint for SAST/code vulnerability findings.
// This is a convenience function for the common SAST case.
func GenerateSAST(filePath, ruleID string, startLine, endLine int) string {
	return Generate(Input{
		Type:      TypeSAST,
		FilePath:  filePath,
		RuleID:    ruleID,
		StartLine: startLine,
		EndLine:   endLine,
	})
}

// GenerateSCA creates a fingerprint for SCA/dependency vulnerability findings.
// This is a convenience function for the common SCA case.
func GenerateSCA(packageName, packageVersion, vulnID string) string {
	return Generate(Input{
		Type:            TypeSCA,
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		VulnerabilityID: vulnID,
	})
}

// GenerateSecret creates a fingerprint for secret detection findings.
// This is a convenience function for the common secret case.
func GenerateSecret(filePath, ruleID string, startLine int, secretValue string) string {
	return Generate(Input{
		Type:        TypeSecret,
		FilePath:    filePath,
		RuleID:      ruleID,
		StartLine:   startLine,
		SecretValue: secretValue,
	})
}

// GenerateMisconfiguration creates a fingerprint for misconfiguration findings.
func GenerateMisconfiguration(resourceType, resourceName, ruleID, filePath string) string {
	return Generate(Input{
		Type:         TypeMisconfiguration,
		ResourceType: resourceType,
		ResourceName: resourceName,
		RuleID:       ruleID,
		FilePath:     filePath,
	})
}

// GenerateGeneric creates a fingerprint for generic findings.
// Use this when the finding type doesn't fit other categories.
func GenerateGeneric(ruleID, filePath string, startLine, endLine int, message string) string {
	return Generate(Input{
		Type:      TypeGeneric,
		RuleID:    ruleID,
		FilePath:  filePath,
		StartLine: startLine,
		EndLine:   endLine,
		Message:   message,
	})
}

// Hash computes SHA256 hash of the input string.
// Returns 64 hex characters.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// normalize cleans up a string for consistent fingerprinting.
// - Trims whitespace
// - Converts to lowercase for case-insensitive matching
// - Normalizes path separators
func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// Normalize Windows paths to Unix style
	s = strings.ReplaceAll(s, "\\", "/")
	return s
}

// DetectType attempts to detect the finding type from available data.
// This is useful when the type is not explicitly provided.
func DetectType(input Input) Type {
	// SCA: Has package and vulnerability info
	if input.PackageName != "" && input.VulnerabilityID != "" {
		return TypeSCA
	}

	// Secret: Has secret value
	if input.SecretValue != "" {
		return TypeSecret
	}

	// Misconfig: Has resource info
	if input.ResourceType != "" || input.ResourceName != "" {
		return TypeMisconfiguration
	}

	// SAST: Has file location with rule
	if input.FilePath != "" && input.RuleID != "" && input.StartLine > 0 {
		return TypeSAST
	}

	return TypeGeneric
}

// GenerateAuto automatically detects the type and generates a fingerprint.
// Use this when you're not sure which specific generator to use.
func GenerateAuto(input Input) string {
	if input.Type == "" {
		input.Type = DetectType(input)
	}
	return Generate(input)
}
