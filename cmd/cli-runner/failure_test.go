package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REAL stdout from `claude -p --output-format json` 2.0.1 given a Claude
// subscription token in ANTHROPIC_API_KEY, captured on an OKD install
// (2026-11-04). The process exited 1 with an EMPTY stderr, so this result is
// the only place the reason exists. Note subtype "success" on an error.
const claudeInvalidKeyStdout = `{"type":"result","subtype":"success","is_error":true,"duration_ms":2982,"duration_api_ms":0,"num_turns":1,"result":"Invalid API key · Fix external API key","session_id":"5c4c7b6a-ece5-407f-ac7f-6a0a8bae6b0c","total_cost_usd":0,"usage":{"input_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0,"server_tool_use":{"web_search_requests":0},"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0}},"modelUsage":{},"permission_denials":[],"uuid":"428b3bf4-0320-4317-b7ba-75e7782871f0"}`

func TestFailureDetailUsesClaudesStdoutWhenStderrIsEmpty(t *testing.T) {
	got := failureDetail(agentSpecs["claude"], []byte(claudeInvalidKeyStdout), nil)
	if !strings.Contains(got, "Invalid API key") {
		t.Fatalf("failureDetail = %q; the CLI's own reason must reach the hub, not an empty string", got)
	}
}

func TestFailureDetailKeepsStderrAndAddsReportedError(t *testing.T) {
	got := failureDetail(agentSpecs["claude"], []byte(claudeInvalidKeyStdout), []byte("node warning\n"))
	if !strings.Contains(got, "node warning") || !strings.Contains(got, "Invalid API key") {
		t.Fatalf("failureDetail = %q, want both stderr and the reported error", got)
	}
}

func TestFailureDetailWithUnparsableStdoutIsStderrOnly(t *testing.T) {
	got := failureDetail(agentSpecs["claude"], []byte("not json"), []byte("boom"))
	if got != "boom" {
		t.Fatalf("failureDetail = %q, want stderr only when stdout carries no reported error", got)
	}
}

func TestCliReportedErrorOmitsSuccessSubtype(t *testing.T) {
	_, err := parseClaudeJSON([]byte(claudeInvalidKeyStdout))
	if err == nil {
		t.Fatal("an is_error result must be an error")
	}
	if msg := err.Error(); strings.Contains(msg, "success") || !strings.Contains(msg, "Invalid API key") {
		t.Fatalf("error = %q; a subtype of \"success\" on an error result is noise, the message is the point", msg)
	}
}

func TestVersionLineSkipsCodexWarning(t *testing.T) {
	out := "WARNING: proceeding, even though we could not create PATH aliases: Permission denied (os error 13)\ncodex-cli 0.154.0\n"
	if got := versionLine(out); got != "codex-cli 0.154.0" {
		t.Fatalf("versionLine = %q, want the version, not the warning", got)
	}
	if got := versionLine("2.0.1 (Claude Code)\n"); got != "2.0.1 (Claude Code)" {
		t.Fatalf("versionLine = %q", got)
	}
}

// OpenShift runs the runner as an arbitrary UID whose HOME is "/", which is
// not writable, and Claude Code fails even `--version` without a writable
// HOME. The stand-in CLI below does the same: it exits 1 unless it can write
// into $HOME. validateAgent must still find it.
func TestValidateAgentWorksWithUnwritableProcessHome(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-claude")
	script := "#!/bin/sh\ntouch \"$HOME/.claude.json\" || exit 1\necho '2.0.1 (Claude Code)'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	readOnly := filepath.Join(dir, "ro-home")
	if err := os.Mkdir(readOnly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", readOnly)
	t.Setenv("ARGUS_CLI_BINARY_CLAUDE", bin)

	got, err := validateAgent("claude")
	if err != nil {
		t.Fatalf("validateAgent: %v (an installed CLI was reported missing because the runner's own HOME is read-only)", err)
	}
	if got != "2.0.1 (Claude Code)" {
		t.Fatalf("version = %q", got)
	}
}
