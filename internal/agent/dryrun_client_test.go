package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
)

func TestLoadDryRunConfig_EmptyTokenDirMeansNotConfigured(t *testing.T) {
	cfg, err := loadDryRunConfig(&rest.Config{Host: "https://example.invalid"}, "")
	if err != nil {
		t.Fatalf("loadDryRunConfig(\"\") returned an error, want nil: %v", err)
	}
	if cfg != nil {
		t.Fatalf("loadDryRunConfig(\"\") = %+v, want nil (the ordinary, disabled-by-default state)", cfg)
	}
}

func TestLoadDryRunConfig_MissingTokenFileIsAnError(t *testing.T) {
	dir := t.TempDir() // exists, but no "token" file inside it
	_, err := loadDryRunConfig(&rest.Config{Host: "https://example.invalid"}, dir)
	if err == nil {
		t.Fatal("loadDryRunConfig succeeded against a directory with no token file, want an error")
	}
}

func TestLoadDryRunConfig_UsesTheMountedTokenNeverThePrimaryCredential(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, dryRunTokenFileName)
	if err := os.WriteFile(tokenPath, []byte("argus-dryrun-token-value"), 0o600); err != nil {
		t.Fatalf("write fixture token: %v", err)
	}

	base := &rest.Config{
		Host:        "https://example.invalid",
		BearerToken: "PRIMARY-IDENTITY-TOKEN-must-not-survive",
	}
	cfg, err := loadDryRunConfig(base, dir)
	if err != nil {
		t.Fatalf("loadDryRunConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("loadDryRunConfig returned nil, want a config")
	}
	if cfg.Host != base.Host {
		t.Errorf("Host = %q, want the same API server as the primary config (%q)", cfg.Host, base.Host)
	}
	if cfg.BearerToken != "" {
		t.Errorf("BearerToken = %q, want empty — the credential must come from BearerTokenFile, never a copied literal token", cfg.BearerToken)
	}
	if cfg.BearerTokenFile != tokenPath {
		t.Errorf("BearerTokenFile = %q, want %q", cfg.BearerTokenFile, tokenPath)
	}
	// base itself must be untouched — loadDryRunConfig must copy, not mutate,
	// the primary identity's own config.
	if base.BearerToken != "PRIMARY-IDENTITY-TOKEN-must-not-survive" {
		t.Errorf("loadDryRunConfig mutated the base config's BearerToken to %q", base.BearerToken)
	}
}

func TestLoadDryRunConfig_PrefersTheMountedCAWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dryRunTokenFileName), []byte("tok"), 0o600); err != nil {
		t.Fatalf("write fixture token: %v", err)
	}
	caPath := filepath.Join(dir, dryRunCAFileName)
	if err := os.WriteFile(caPath, []byte("fixture-ca-bytes"), 0o600); err != nil {
		t.Fatalf("write fixture ca: %v", err)
	}

	cfg, err := loadDryRunConfig(&rest.Config{Host: "https://example.invalid"}, dir)
	if err != nil {
		t.Fatalf("loadDryRunConfig: %v", err)
	}
	if cfg.TLSClientConfig.CAFile != caPath {
		t.Errorf("CAFile = %q, want %q", cfg.TLSClientConfig.CAFile, caPath)
	}
}

func TestGatherClusterDryRunAuthority_EmptyTokenDirReportsNotChecked(t *testing.T) {
	got := gatherClusterDryRunAuthority(context.Background(), "")
	if got.Checked {
		t.Errorf("Checked = true for an empty token dir, want false (the ordinary 'never opted in' state)")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty — this is not a failure, just the default state", got.Error)
	}
	if got.Allowed {
		t.Errorf("Allowed = true for an unchecked result, want false")
	}
}

func TestGatherClusterDryRunAuthority_MisconfiguredMountReportsUncheckedWithReason(t *testing.T) {
	// A directory that exists but holds no token file — dryRun.enabled was
	// set, but something about the mount is broken. Must be reported as
	// "unknown, here's why", never as a confident denial.
	got := gatherClusterDryRunAuthority(context.Background(), t.TempDir())
	if got.Checked {
		t.Errorf("Checked = true for a broken mount, want false")
	}
	if got.Error == "" {
		t.Error("Error is empty for a genuine misconfiguration, want a reason")
	}
}
