package semgrep

import (
	"context"
	"testing"

	"github.com/rediverio/sdk/pkg/core"
	"github.com/rediverio/sdk/pkg/ris"
)

func TestParser_CreateAssetFromOptions(t *testing.T) {
	parser := &Parser{}

	tests := []struct {
		name          string
		opts          *core.ParseOptions
		wantAsset     bool
		wantAssetName string
		wantAssetType ris.AssetType
	}{
		{
			name:      "nil options returns nil asset",
			opts:      nil,
			wantAsset: false,
		},
		{
			name:      "empty options returns nil asset",
			opts:      &core.ParseOptions{},
			wantAsset: false,
		},
		{
			name: "AssetValue creates asset",
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
				AssetType:  ris.AssetTypeRepository,
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ris.AssetTypeRepository,
		},
		{
			name: "BranchInfo creates asset when AssetValue is empty",
			opts: &core.ParseOptions{
				BranchInfo: &ris.BranchInfo{
					RepositoryURL:   "gitlab.com/mygroup/myproject",
					Name:            "develop",
					CommitSHA:       "def456",
					IsDefaultBranch: false,
				},
			},
			wantAsset:     true,
			wantAssetName: "gitlab.com/mygroup/myproject",
			wantAssetType: ris.AssetTypeRepository,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := parser.createAssetFromOptions(tt.opts)

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
	parser := &Parser{}

	// Minimal semgrep output (no findings)
	data := []byte(`{"version": "1.0.0", "results": []}`)

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
}
