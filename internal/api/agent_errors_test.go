package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"argus/internal/gateway"
)

// The live defect: every failed inspection read "it may not support it yet,
// or the object may not exist", though the agent had said exactly why
// (a ContainerCreating pod has no logs; a container that never restarted has
// no previous log). The agent's own reason now reaches the person.
func TestAgentToolFailureDetailPassesTheAgentsReason(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &gateway.ToolError{ClusterID: "cl_1", Tool: "get_logs",
		Message: "container app in pod apps/web-1 has not started yet (ContainerCreating), so it has no logs"})
	got := agentToolFailureDetail(err)
	want := "The agent reported: container app in pod apps/web-1 has not started yet (ContainerCreating), so it has no logs."
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestAgentToolFailureDetailTidiesAndBounds(t *testing.T) {
	msg := "line one\n\tline\x00two  " + strings.Repeat("x", 500)
	got := agentToolFailureDetail(&gateway.ToolError{Message: msg})
	if strings.ContainsAny(got, "\n\t\x00") {
		t.Fatalf("control characters survived: %q", got)
	}
	if !strings.HasPrefix(got, "The agent reported: line one linetwo ") {
		t.Fatalf("whitespace not collapsed: %q", got[:60])
	}
	if !strings.HasSuffix(got, "…") || len([]rune(got)) > maxAgentReasonRunes+40 {
		t.Fatalf("not bounded: %d runes", len([]rune(got)))
	}
	if got := agentToolFailureDetail(&gateway.ToolError{Message: "  "}); got != "The agent reported a failure but gave no reason." {
		t.Fatalf("empty reason: %q", got)
	}
}

// A transport failure is described by its kind, never by its raw text, which
// can carry internal addresses.
func TestAgentToolFailureDetailHidesTransportErrors(t *testing.T) {
	got := agentToolFailureDetail(fmt.Errorf("gateway: send to 10.1.2.3:8443: %w", errors.New("broken pipe")))
	if strings.Contains(got, "10.1.2.3") || strings.Contains(got, "broken pipe") {
		t.Fatalf("transport text leaked: %q", got)
	}
	if got := agentToolFailureDetail(fmt.Errorf("x: %w", context.DeadlineExceeded)); !strings.Contains(got, "did not answer in time") {
		t.Fatalf("timeout: %q", got)
	}
}

// The agent answering "that object is not there" is a 404, not an agent
// failure; anything else — a real tool error, a transport failure — is not.
func TestIsAgentNotFound(t *testing.T) {
	for _, msg := range []string{"Pod apps/web-1 not found", "resource not found", "Deployment apps/web not found.", "service shop/cart not found"} {
		if !isAgentNotFound(fmt.Errorf("wrap: %w", &gateway.ToolError{Message: msg})) {
			t.Errorf("%q: want not-found", msg)
		}
	}
	for _, err := range []error{
		&gateway.ToolError{Message: "permission denied"},
		&gateway.ToolError{Message: "kubernetes API request failed"},
		&gateway.ToolError{Message: "not found in the object cache, which is still syncing; try again"},
		errors.New("gateway: cluster disconnected: not found"),
		fmt.Errorf("x: %w", context.DeadlineExceeded),
	} {
		if isAgentNotFound(err) {
			t.Errorf("%v: must not read as not-found", err)
		}
	}
}
