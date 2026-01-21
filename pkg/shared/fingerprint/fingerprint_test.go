// Package fingerprint provides unified fingerprint generation algorithms.
package fingerprint

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple string", "hello"},
		{"complex string", "sast:src/main.go:rule-001:10:20"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := Hash(tt.input)

			// SHA256 hash should be 64 hex characters
			if len(hash) != 64 {
				t.Errorf("Hash(%q) length = %d, want 64", tt.input, len(hash))
			}

			// Should be deterministic
			hash2 := Hash(tt.input)
			if hash != hash2 {
				t.Errorf("Hash is not deterministic: %s != %s", hash, hash2)
			}

			// Should only contain hex characters
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Hash contains non-hex character: %c", c)
				}
			}
		})
	}
}

func TestHash_Different(t *testing.T) {
	hash1 := Hash("input1")
	hash2 := Hash("input2")

	if hash1 == hash2 {
		t.Errorf("Different inputs should produce different hashes")
	}
}

func TestGenerate_SAST(t *testing.T) {
	input := Input{
		Type:      TypeSAST,
		FilePath:  "src/main.go",
		RuleID:    "go-sec-001",
		StartLine: 10,
		EndLine:   15,
	}

	fingerprint := Generate(input)

	// Should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}

	// Same input should produce same fingerprint
	fingerprint2 := Generate(input)
	if fingerprint != fingerprint2 {
		t.Errorf("Same input produced different fingerprints")
	}

	// Different line should produce different fingerprint
	input.StartLine = 20
	fingerprint3 := Generate(input)
	if fingerprint == fingerprint3 {
		t.Errorf("Different line should produce different fingerprint")
	}
}

func TestGenerate_SCA(t *testing.T) {
	input := Input{
		Type:            TypeSCA,
		PackageName:     "lodash",
		PackageVersion:  "4.17.20",
		VulnerabilityID: "CVE-2021-23337",
	}

	fingerprint := Generate(input)

	// Should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}

	// Different CVE should produce different fingerprint
	input.VulnerabilityID = "CVE-2021-23338"
	fingerprint2 := Generate(input)
	if fingerprint == fingerprint2 {
		t.Errorf("Different CVE should produce different fingerprint")
	}
}

func TestGenerate_Secret(t *testing.T) {
	input := Input{
		Type:        TypeSecret,
		FilePath:    ".env",
		RuleID:      "aws-access-key",
		StartLine:   5,
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
	}

	fingerprint := Generate(input)

	// Should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}

	// Different secret at same location should produce different fingerprint
	input.SecretValue = "AKIAIOSFODNN7DIFFERENT"
	fingerprint2 := Generate(input)
	if fingerprint == fingerprint2 {
		t.Errorf("Different secret should produce different fingerprint")
	}
}

func TestGenerate_Secret_NoSecretValue(t *testing.T) {
	// Test that empty secret value doesn't cause issues
	input := Input{
		Type:        TypeSecret,
		FilePath:    ".env",
		RuleID:      "api-key",
		StartLine:   10,
		SecretValue: "", // Empty
	}

	fingerprint := Generate(input)
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestGenerate_Misconfiguration(t *testing.T) {
	input := Input{
		Type:         TypeMisconfiguration,
		ResourceType: "aws_s3_bucket",
		ResourceName: "my-bucket",
		RuleID:       "s3-public-access",
		FilePath:     "main.tf",
	}

	fingerprint := Generate(input)

	// Should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}

	// Different resource should produce different fingerprint
	input.ResourceName = "other-bucket"
	fingerprint2 := Generate(input)
	if fingerprint == fingerprint2 {
		t.Errorf("Different resource should produce different fingerprint")
	}
}

func TestGenerate_Generic(t *testing.T) {
	input := Input{
		Type:      TypeGeneric,
		RuleID:    "custom-rule",
		FilePath:  "file.txt",
		StartLine: 1,
		EndLine:   10,
		Message:   "Some finding message",
	}

	fingerprint := Generate(input)

	// Should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestGenerate_UnknownType(t *testing.T) {
	input := Input{
		Type:      Type("unknown"),
		RuleID:    "rule",
		FilePath:  "file.go",
		StartLine: 1,
		EndLine:   5,
		Message:   "message",
	}

	fingerprint := Generate(input)

	// Should fall back to generic type
	if len(fingerprint) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestGenerateSAST(t *testing.T) {
	fp := GenerateSAST("src/main.go", "sql-injection", 42, 50)

	// Should be 64 hex characters
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2 := GenerateSAST("src/main.go", "sql-injection", 42, 50)
	if fp != fp2 {
		t.Errorf("GenerateSAST is not deterministic")
	}
}

func TestGenerateSCA(t *testing.T) {
	fp := GenerateSCA("axios", "0.21.0", "CVE-2021-3749")

	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2 := GenerateSCA("axios", "0.21.0", "CVE-2021-3749")
	if fp != fp2 {
		t.Errorf("GenerateSCA is not deterministic")
	}
}

func TestGenerateSecret(t *testing.T) {
	fp := GenerateSecret(".env", "api-key-detected", 5, "sk-1234567890")

	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2 := GenerateSecret(".env", "api-key-detected", 5, "sk-1234567890")
	if fp != fp2 {
		t.Errorf("GenerateSecret is not deterministic")
	}
}

func TestGenerateMisconfiguration(t *testing.T) {
	fp := GenerateMisconfiguration("aws_security_group", "allow-all", "security-group-open", "main.tf")

	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2 := GenerateMisconfiguration("aws_security_group", "allow-all", "security-group-open", "main.tf")
	if fp != fp2 {
		t.Errorf("GenerateMisconfiguration is not deterministic")
	}
}

func TestGenerateGeneric(t *testing.T) {
	fp := GenerateGeneric("custom-check", "config.yaml", 1, 10, "Configuration issue found")

	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2 := GenerateGeneric("custom-check", "config.yaml", 1, 10, "Configuration issue found")
	if fp != fp2 {
		t.Errorf("GenerateGeneric is not deterministic")
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  HELLO  ", "hello"},
		{"SRC\\Main.go", "src/main.go"},
		{"PATH/TO/FILE", "path/to/file"},
		{"  Spaces\t", "spaces"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalize(tt.input)
			if got != tt.expected {
				t.Errorf("normalize(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGenerate_CaseInsensitive(t *testing.T) {
	// FilePath should be case-insensitive
	fp1 := GenerateSAST("SRC/MAIN.GO", "rule", 10, 20)
	fp2 := GenerateSAST("src/main.go", "RULE", 10, 20)

	if fp1 != fp2 {
		t.Errorf("Fingerprints should be case-insensitive: %s != %s", fp1, fp2)
	}
}

func TestGenerate_PathNormalization(t *testing.T) {
	// Windows paths should be normalized to Unix style
	fp1 := GenerateSAST("src\\main\\app.go", "rule", 10, 20)
	fp2 := GenerateSAST("src/main/app.go", "rule", 10, 20)

	if fp1 != fp2 {
		t.Errorf("Windows paths should be normalized: %s != %s", fp1, fp2)
	}
}

func TestDetectType(t *testing.T) {
	tests := []struct {
		name     string
		input    Input
		expected Type
	}{
		{
			"SCA detection",
			Input{PackageName: "lodash", VulnerabilityID: "CVE-2021-1234"},
			TypeSCA,
		},
		{
			"Secret detection",
			Input{SecretValue: "sk-1234567890"},
			TypeSecret,
		},
		{
			"Misconfig detection - resource type",
			Input{ResourceType: "aws_s3_bucket"},
			TypeMisconfiguration,
		},
		{
			"Misconfig detection - resource name",
			Input{ResourceName: "my-bucket"},
			TypeMisconfiguration,
		},
		{
			"SAST detection",
			Input{FilePath: "main.go", RuleID: "rule-001", StartLine: 10},
			TypeSAST,
		},
		{
			"Generic fallback - missing start line",
			Input{FilePath: "main.go", RuleID: "rule-001"},
			TypeGeneric,
		},
		{
			"Generic fallback - empty input",
			Input{},
			TypeGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectType(tt.input); got != tt.expected {
				t.Errorf("DetectType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateAuto(t *testing.T) {
	// Test auto-detection with SCA data
	input := Input{
		PackageName:     "express",
		PackageVersion:  "4.17.1",
		VulnerabilityID: "CVE-2022-24999",
	}

	fp := GenerateAuto(input)
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Same as explicit SCA
	fpExplicit := GenerateSCA("express", "4.17.1", "CVE-2022-24999")
	if fp != fpExplicit {
		t.Errorf("GenerateAuto should match GenerateSCA for SCA data")
	}
}

func TestGenerateAuto_WithExplicitType(t *testing.T) {
	input := Input{
		Type:     TypeSAST,
		FilePath: "app.go",
		RuleID:   "rule-001",
		// Also has SCA data (should be ignored since Type is set)
		PackageName:     "some-package",
		VulnerabilityID: "CVE-2021-1234",
	}

	fp := GenerateAuto(input)

	// Should use SAST algorithm since Type is explicit
	fpSAST := GenerateSAST("app.go", "rule-001", 0, 0)
	if fp != fpSAST {
		t.Errorf("GenerateAuto should use explicit type when set")
	}
}

// Benchmark tests
func BenchmarkHash(b *testing.B) {
	data := "sast:src/main.go:sql-injection:42:50"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkGenerate_SAST(b *testing.B) {
	input := Input{
		Type:      TypeSAST,
		FilePath:  "src/main/java/com/example/App.java",
		RuleID:    "java-sql-injection",
		StartLine: 42,
		EndLine:   50,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Generate(input)
	}
}

func BenchmarkGenerateSAST(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSAST("src/main.go", "sql-injection", 42, 50)
	}
}

func BenchmarkGenerateSCA(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSCA("lodash", "4.17.20", "CVE-2021-23337")
	}
}

func BenchmarkGenerateSecret(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSecret(".env", "aws-key", 5, "AKIAIOSFODNN7EXAMPLE")
	}
}

func BenchmarkDetectType(b *testing.B) {
	input := Input{
		PackageName:     "lodash",
		VulnerabilityID: "CVE-2021-23337",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectType(input)
	}
}

// Test for collision resistance
func TestGenerate_NoCollisions(t *testing.T) {
	// Generate fingerprints for similar but different inputs
	fingerprints := make(map[string]string)

	inputs := []Input{
		{Type: TypeSAST, FilePath: "file.go", RuleID: "rule1", StartLine: 10, EndLine: 20},
		{Type: TypeSAST, FilePath: "file.go", RuleID: "rule2", StartLine: 10, EndLine: 20},
		{Type: TypeSAST, FilePath: "file.go", RuleID: "rule1", StartLine: 11, EndLine: 20},
		{Type: TypeSAST, FilePath: "file.go", RuleID: "rule1", StartLine: 10, EndLine: 21},
		{Type: TypeSAST, FilePath: "file2.go", RuleID: "rule1", StartLine: 10, EndLine: 20},
		{Type: TypeSCA, PackageName: "pkg1", PackageVersion: "1.0.0", VulnerabilityID: "CVE-1"},
		{Type: TypeSCA, PackageName: "pkg1", PackageVersion: "1.0.1", VulnerabilityID: "CVE-1"},
		{Type: TypeSCA, PackageName: "pkg1", PackageVersion: "1.0.0", VulnerabilityID: "CVE-2"},
		{Type: TypeSCA, PackageName: "pkg2", PackageVersion: "1.0.0", VulnerabilityID: "CVE-1"},
	}

	for i, input := range inputs {
		fp := Generate(input)
		key := fp

		if existing, ok := fingerprints[key]; ok {
			t.Errorf("Collision detected between input %d and existing: %s", i, existing)
		}
		fingerprints[key] = strings.TrimSpace(string(rune(i)))
	}
}
