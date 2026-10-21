package gitops

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// applyDiffOps reconstructs the "after" text from "before" plus an edit
// script. This is the load-bearing correctness check for every test below: it
// does not assume which of possibly-several shortest edit scripts the
// algorithm picked, only that replaying whichever one it picked against
// `before` reproduces `after` exactly.
func applyDiffOps(before []string, ops []diffOp) []string {
	var out []string
	i := 0
	for _, op := range ops {
		switch op.Kind {
		case diffEqual:
			if i >= len(before) || before[i] != op.Text {
				panic(fmt.Sprintf("diffEqual op %q does not match before[%d]=%q", op.Text, i, safeIndex(before, i)))
			}
			out = append(out, before[i])
			i++
		case diffDelete:
			if i >= len(before) || before[i] != op.Text {
				panic(fmt.Sprintf("diffDelete op %q does not match before[%d]=%q", op.Text, i, safeIndex(before, i)))
			}
			i++
		case diffInsert:
			out = append(out, op.Text)
		}
	}
	if i != len(before) {
		panic(fmt.Sprintf("edit script consumed %d of %d lines of before", i, len(before)))
	}
	return out
}

func safeIndex(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return "<out of range>"
	}
	return s[i]
}

func assertReconstructs(t *testing.T, before, after []string) []diffOp {
	t.Helper()
	ops := myersLineDiff(before, after)
	got := applyDiffOps(before, ops)
	if !equalStrings(got, after) {
		t.Fatalf("applying the edit script did not reproduce after:\n got:  %#v\n want: %#v\n ops: %#v", got, after, ops)
	}
	return ops
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMyersLineDiffReconstructs(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		after  []string
	}{
		{"identical", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"both empty", nil, nil},
		{"before empty, pure insert", nil, []string{"a", "b"}},
		{"after empty, pure delete", []string{"a", "b"}, nil},
		{"append at end", []string{"a", "b"}, []string{"a", "b", "c", "d"}},
		{"prepend at start", []string{"c", "d"}, []string{"a", "b", "c", "d"}},
		{"insert in middle", []string{"a", "d"}, []string{"a", "b", "c", "d"}},
		{"delete from middle", []string{"a", "b", "c", "d"}, []string{"a", "d"}},
		{"single line replaced", []string{"a", "b", "c"}, []string{"a", "X", "c"}},
		{"completely different", []string{"a", "b", "c"}, []string{"x", "y", "z"}},
		{"reordered", []string{"a", "b", "c"}, []string{"c", "b", "a"}},
		{"duplicate lines", []string{"x", "x", "x"}, []string{"x", "x"}},
		{"trailing blank line added", []string{"a", "b"}, []string{"a", "b", ""}},
		{"whole file replaced with shorter", []string{"a", "b", "c", "d", "e"}, []string{"z"}},
		{"whole file replaced with longer", []string{"z"}, []string{"a", "b", "c", "d", "e"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertReconstructs(t, c.before, c.after)
		})
	}
}

// TestMyersLineDiffFuzz generates random small before/after pairs and checks
// the same reconstruction property holds for all of them — a diff algorithm's
// correctness bug is exactly the kind of thing a handful of hand-picked cases
// can miss.
func TestMyersLineDiffFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "b", "c", "d", "e"}
	randLines := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return out
	}
	for i := 0; i < 500; i++ {
		before := randLines(rng.Intn(12))
		after := randLines(rng.Intn(12))
		assertReconstructs(t, before, after)
	}
}

func TestCommonAffixDiffReconstructs(t *testing.T) {
	before := []string{"a", "b", "c", "d", "e"}
	after := []string{"a", "b", "X", "Y", "d", "e"}
	ops := commonAffixDiff(before, after)
	got := applyDiffOps(before, ops)
	if !equalStrings(got, after) {
		t.Fatalf("commonAffixDiff did not reconstruct: got %#v want %#v", got, after)
	}
	// The common prefix/suffix must be reported as equal, not redundantly
	// rewritten — that is the whole point of computing them.
	if ops[0].Kind != diffEqual || ops[0].Text != "a" {
		t.Fatalf("expected the common prefix to be reported as equal, got %#v", ops[0])
	}
	if last := ops[len(ops)-1]; last.Kind != diffEqual || last.Text != "e" {
		t.Fatalf("expected the common suffix to be reported as equal, got %#v", last)
	}
}

func TestFreeformLineDiffFallsBackAboveThreshold(t *testing.T) {
	// A combined line count over maxMyersOps must use the bounded fallback
	// rather than the full algorithm, and must still reconstruct correctly.
	before := make([]string, maxMyersOps)
	after := make([]string, maxMyersOps)
	for i := range before {
		before[i] = fmt.Sprintf("line-%d", i)
		after[i] = before[i]
	}
	after[len(after)/2] = "CHANGED"
	ops := freeformLineDiff(before, after)
	got := applyDiffOps(before, ops)
	if !equalStrings(got, after) {
		t.Fatalf("fallback diff did not reconstruct correctly")
	}
}

func TestFreeformUnifiedDiffRendersGitStyleHunks(t *testing.T) {
	before := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	after := make([]string, len(before))
	copy(after, before)
	after[4] = "CHANGED" // 0-based index 4 -> line 5

	diff, added, removed := freeformUnifiedDiff(before, after)
	if added != 1 || removed != 1 {
		t.Fatalf("expected 1 added and 1 removed line, got added=%d removed=%d\n%s", added, removed, diff)
	}
	if !strings.Contains(diff, "@@ -2,7 +2,7 @@") {
		t.Fatalf("expected a hunk header with 3 lines of context on each side, got:\n%s", diff)
	}
	if !strings.Contains(diff, "-e\n") || !strings.Contains(diff, "+CHANGED\n") {
		t.Fatalf("expected the changed line to show as -e/+CHANGED, got:\n%s", diff)
	}
	// Lines far from the change must not appear at all — a diff that dumped
	// the whole file would defeat the point of hunking.
	if strings.Contains(diff, "\na\n") || strings.Contains(diff, " a\n") {
		t.Fatalf("expected line 'a' (far outside context) to be excluded from the diff, got:\n%s", diff)
	}
}

func TestFreeformUnifiedDiffMergesCloseHunks(t *testing.T) {
	// Two changes 4 lines apart (fewer than 2*context=6 lines of untouched
	// content between them) must merge into a single hunk, not two.
	before := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	after := make([]string, len(before))
	copy(after, before)
	after[1] = "TWO"
	after[6] = "SEVEN"

	diff, added, removed := freeformUnifiedDiff(before, after)
	if added != 2 || removed != 2 {
		t.Fatalf("expected 2 added and 2 removed, got added=%d removed=%d\n%s", added, removed, diff)
	}
	if strings.Count(diff, "@@") != 2 {
		t.Fatalf("expected exactly one hunk (one '@@ ... @@' header, 2 '@@' tokens), got:\n%s", diff)
	}
}

func TestFreeformUnifiedDiffNoChangeIsEmpty(t *testing.T) {
	lines := []string{"a", "b", "c"}
	diff, added, removed := freeformUnifiedDiff(lines, lines)
	if diff != "" || added != 0 || removed != 0 {
		t.Fatalf("expected no diff for identical input, got diff=%q added=%d removed=%d", diff, added, removed)
	}
}
