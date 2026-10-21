package conditionpolarity

import (
	"context"
	"errors"
	"testing"
)

// fakeAsker is a hand-rolled ModelAsker for the pure-logic tests in this
// file — no DB, no real model, matching this package's own reasoning for
// why ModelAsker is a narrow interface rather than *llm.Provider directly.
type fakeAsker struct {
	text  string
	model string
	err   error
}

func (f fakeAsker) Ask(_ context.Context, _, _ string) (string, string, error) {
	return f.text, f.model, f.err
}

func TestOtherValue(t *testing.T) {
	if got := otherValue("True"); got != "False" {
		t.Fatalf("otherValue(True) = %q, want False", got)
	}
	if got := otherValue("False"); got != "True" {
		t.Fatalf("otherValue(False) = %q, want True", got)
	}
}

func TestAskModelPolarity_ParsesVariants(t *testing.T) {
	cases := []struct {
		reply string
		want  string
	}{
		{"True", "True"},
		{"true", "True"},
		{"  True  ", "True"},
		{"\"True\"", "True"},
		{"True.", "True"},
		{"False", "False"},
		{"false", "False"},
	}
	for _, c := range cases {
		bad, model, err := askModelPolarity(context.Background(), fakeAsker{text: c.reply, model: "test-model"}, "Node", "MemoryPressure")
		if err != nil {
			t.Fatalf("reply %q: unexpected error: %v", c.reply, err)
		}
		if bad != c.want {
			t.Fatalf("reply %q: got %q, want %q", c.reply, bad, c.want)
		}
		if model != "test-model" {
			t.Fatalf("reply %q: expected model name to be threaded through, got %q", c.reply, model)
		}
	}
}

func TestAskModelPolarity_UnparseableReply_ErrorsRatherThanGuessing(t *testing.T) {
	_, _, err := askModelPolarity(context.Background(), fakeAsker{text: "It depends on the controller."}, "Widget", "Ready")
	if err == nil {
		t.Fatalf("expected an error for an unparseable reply, got nil (non-negotiable 8: never guess)")
	}
}

func TestAskModelPolarity_AskerError_Propagated(t *testing.T) {
	wantErr := errors.New("boom")
	_, _, err := askModelPolarity(context.Background(), fakeAsker{err: wantErr}, "Widget", "Ready")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected the asker's own error to be wrapped and returned, got %v", err)
	}
}
