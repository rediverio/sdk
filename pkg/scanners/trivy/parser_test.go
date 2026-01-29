package trivy

import (
	"context"
	"testing"

	"github.com/rediverio/sdk/pkg/core"
	"github.com/rediverio/sdk/pkg/ris"
)

func TestParser_CreateAssetFromContext(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name          string
		report        *Report
		opts          *core.ParseOptions
		wantAsset     bool
		wantAssetName string
		wantAssetType ris.AssetType
	}{
		{
			name:      "nil options and empty report returns nil asset",
			report:    &Report{},
			opts:      nil,
			wantAsset: false,
		},
		{
			name: "AssetValue takes priority over artifact",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
				AssetType:  ris.AssetTypeRepository,
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ris.AssetTypeRepository,
		},
		{
			name: "BranchInfo takes priority over artifact",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts: &core.ParseOptions{
				BranchInfo: &ris.BranchInfo{
					RepositoryURL:   "github.com/org/repo",
					Name:            "main",
					IsDefaultBranch: true,
				},
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ris.AssetTypeRepository,
		},
		{
			name: "falls back to artifact when no options",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts:          nil,
			wantAsset:     true,
			wantAssetName: "myimage:latest",
			wantAssetType: ris.AssetTypeContainer,
		},
		{
			name: "falls back to artifact when options are empty",
			report: &Report{
				ArtifactName: ".",
				ArtifactType: "filesystem",
			},
			opts:          &core.ParseOptions{},
			wantAsset:     true,
			wantAssetName: ".",
			wantAssetType: ris.AssetTypeRepository,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := parser.createAssetFromContext(tt.report, tt.opts)

			if tt.wantAsset {
				if asset == nil {
					t.Fatalf("expected asset, got nil")
				}
				if asset.Name != tt.wantAssetName {
					t.Errorf("asset name = %q, want %q", asset.Name, tt.wantAssetName)
				}
				if asset.Type != tt.wantAssetType {
					t.Errorf("asset type = %q, want %q", asset.Type, tt.wantAssetType)
				}
			} else {
				if asset != nil {
					t.Errorf("expected nil asset, got %+v", asset)
				}
			}
		})
	}
}

func TestParser_ParseWithAssetFromBranchInfo(t *testing.T) {
	parser := NewParser()

	// Minimal trivy output
	data := []byte(`{"SchemaVersion": 2, "Results": []}`)

	opts := &core.ParseOptions{
		BranchInfo: &ris.BranchInfo{
			RepositoryURL:   "github.com/myorg/myrepo",
			Name:            "main",
			CommitSHA:       "abc123",
			IsDefaultBranch: true,
		},
	}

	report, err := parser.Parse(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(report.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(report.Assets))
	}

	asset := report.Assets[0]
	if asset.Value != "github.com/myorg/myrepo" {
		t.Errorf("asset value = %q, want %q", asset.Value, "github.com/myorg/myrepo")
	}
	if asset.Type != ris.AssetTypeRepository {
		t.Errorf("asset type = %q, want %q", asset.Type, ris.AssetTypeRepository)
	}

	// Verify properties
	if asset.Properties["source"] != "branch_info" {
		t.Errorf("asset source = %v, want branch_info", asset.Properties["source"])
	}
}

func TestParser_HasAssetInfo(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name string
		opts *core.ParseOptions
		want bool
	}{
		{
			name: "nil options",
			opts: nil,
			want: false,
		},
		{
			name: "empty options",
			opts: &core.ParseOptions{},
			want: false,
		},
		{
			name: "with AssetValue",
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
			},
			want: true,
		},
		{
			name: "with BranchInfo.RepositoryURL",
			opts: &core.ParseOptions{
				BranchInfo: &ris.BranchInfo{
					RepositoryURL: "github.com/org/repo",
				},
			},
			want: true,
		},
		{
			name: "with empty BranchInfo",
			opts: &core.ParseOptions{
				BranchInfo: &ris.BranchInfo{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.hasAssetInfo(tt.opts)
			if got != tt.want {
				t.Errorf("hasAssetInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
