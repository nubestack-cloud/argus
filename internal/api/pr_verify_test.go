package api

import (
	"context"
	"errors"
	"testing"

	"argus/internal/scm"
)

// TestSplitLiveFieldPathAcceptsEveryNotation matches the same three notations
// remediation.normaliseFieldPath already
// accept — one model-facing convention, three places that parse it.
func TestSplitLiveFieldPathAcceptsEveryNotation(t *testing.T) {
	want := []string{"spec", "template", "spec", "containers", "0", "image"}
	for _, in := range []string{
		"spec.template.spec.containers[0].image",
		"spec/template/spec/containers/0/image",
		"spec.template.spec.containers.0.image",
	} {
		got := splitLiveFieldPath(in)
		if len(got) != len(want) {
			t.Fatalf("splitLiveFieldPath(%q) = %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitLiveFieldPath(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

// TestNestedFieldAtPathWalksMapsAndLists is the read-side counterpart of
// internal/agent's TestNestedFieldAt (unexported there, so not directly
// reusable) — same algorithm, exercised against the plain
// map[string]any/[]any shape describe_resource actually returns hub-side.
func TestNestedFieldAtPathWalksMapsAndLists(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"replicas": float64(3),
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "web", "image": "nginx:1.27-alpine"},
					},
				},
			},
		},
	}

	if v, found, err := nestedFieldAtPath(obj, []string{"spec", "replicas"}); err != nil || !found || v.(float64) != 3 {
		t.Errorf("spec.replicas = %v, %v, %v; want 3, true, nil", v, found, err)
	}

	if v, found, err := nestedFieldAtPath(obj, []string{"spec", "template", "spec", "containers", "0", "image"}); err != nil || !found || v != "nginx:1.27-alpine" {
		t.Errorf("containers[0].image = %v, %v, %v; want nginx:1.27-alpine, true, nil", v, found, err)
	}

	if _, found, err := nestedFieldAtPath(obj, []string{"spec", "noSuchField"}); err != nil || found {
		t.Errorf("missing field: found=%v err=%v, want found=false err=nil", found, err)
	}

	if _, found, err := nestedFieldAtPath(obj, []string{"spec", "template", "spec", "containers", "9", "image"}); err != nil || found {
		t.Errorf("out-of-range index: found=%v err=%v, want found=false err=nil", found, err)
	}

	if _, _, err := nestedFieldAtPath(obj, []string{"spec", "replicas", "tooDeep"}); err == nil {
		t.Error("indexing past a scalar should error, got nil")
	}

	if _, _, err := nestedFieldAtPath(obj, []string{"spec", "template", "spec", "containers", "notAnInt"}); err == nil {
		t.Error("a non-numeric segment into a list should error, got nil")
	}
}

// TestStringifyLiveValueRendersWholeNumbersWithoutDecimalNoise: every JSON
// number decodes to float64, and a whole-number field (replicas, a port) must
// compare equal to the plain integer string an earlier build recorded — not
// to whatever fmt's default float formatting happens to produce.
func TestStringifyLiveValueRendersWholeNumbersWithoutDecimalNoise(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{float64(3), "3"},
		{float64(8080), "8080"},
		{float64(0), "0"},
		{"nginx:1.27-alpine", "nginx:1.27-alpine"},
		{true, "true"},
	}
	for _, tc := range cases {
		if got := stringifyLiveValue(tc.in); got != tc.want {
			t.Errorf("stringifyLiveValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// fakeReadFileProvider satisfies scm.Provider by embedding it as a nil
// interface and overriding only ReadFile — the same pattern
// mergecheck_test.go's fakeIsAncestorProvider uses for IsAncestor.
// compareProposedFilesAtRevision is the only thing under test in the cases
// below, and it calls nothing else on the interface.
type fakeReadFileProvider struct {
	scm.Provider
	// content maps path -> content ReadFile should return for it. A path
	// absent from this map returns scm.ErrNotFound, simulating a file that
	// existed when the pull request merged but does not exist at the
	// revision being checked.
	content map[string]string
	err     error
	calls   []string
}

func (f *fakeReadFileProvider) ReadFile(_ context.Context, _ scm.Repo, _ string, path string) ([]byte, error) {
	f.calls = append(f.calls, path)
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.content[path]
	if !ok {
		return nil, scm.ErrNotFound
	}
	return []byte(c), nil
}

// TestCompareProposedFilesAtRevision_Holds is BACKLOG.md F23's case (a): a
// merged pull request whose files, re-read at the synced revision, still
// match what was proposed — the assertion holds and raises no false alarm.
func TestCompareProposedFilesAtRevision_Holds(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{
		"envs/prod/deployment.yaml": "replicas: 3\n",
		"envs/prod/values.yaml":     "image: nginx:1.27\n",
	}}
	proposed := []prProposedFile{
		{Path: "envs/prod/deployment.yaml", Content: "replicas: 3\n"},
		{Path: "envs/prod/values.yaml", Content: "image: nginx:1.27\n"},
	}
	held, detail, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !held {
		t.Fatalf("held = false, want true — every file matched. detail: %s", detail)
	}
	if len(p.calls) != 2 {
		t.Errorf("ReadFile called %d times, want 2 (one per proposed file)", len(p.calls))
	}
}

// TestCompareProposedFilesAtRevision_Mismatch is BACKLOG.md F23's case (b): a
// merged pull request whose synced content does NOT match what was proposed
// — simulating a revert or a conflicting concurrent change landing after the
// merge — must be flagged (held=false), not silently passed.
func TestCompareProposedFilesAtRevision_Mismatch(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{
		// Reverted back to the pre-fix value after the merge.
		"envs/prod/deployment.yaml": "replicas: 1\n",
	}}
	proposed := []prProposedFile{
		{Path: "envs/prod/deployment.yaml", Content: "replicas: 3\n"},
	}
	held, detail, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err != nil {
		t.Fatalf("err = %v, want nil — a mismatch is a verdict, not a failed check", err)
	}
	if held {
		t.Fatal("held = true, want false — the synced content does not match what was merged")
	}
	if detail == "" {
		t.Error("detail is empty, want an explanation naming the file")
	}
}

// TestCompareProposedFilesAtRevision_FileDeleted covers the sharper form of
// the same failure: the file this pull request changed no longer exists at
// all at the synced revision (deleted by something after the merge). A
// missing file is scm.ErrNotFound, which must be read as "does not hold"
// rather than as an inconclusive error.
func TestCompareProposedFilesAtRevision_FileDeleted(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{}}
	proposed := []prProposedFile{
		{Path: "envs/prod/deployment.yaml", Content: "replicas: 3\n"},
	}
	held, detail, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if held {
		t.Fatal("held = true, want false — the file no longer exists at the synced revision")
	}
	if detail == "" {
		t.Error("detail is empty, want an explanation naming the file")
	}
}

// TestCompareProposedFilesAtRevision_DeletedFileStillAbsentHolds is
// BACKLOG.md "still open" #2's post-merge half: a pull request that DELETED
// a file, re-checked at the currently synced revision, holds when the file
// is STILL absent — the inverse of what an ordinary written file's own
// ErrNotFound means (compare TestCompareProposedFilesAtRevision_FileDeleted,
// where absence is the failure).
func TestCompareProposedFilesAtRevision_DeletedFileStillAbsentHolds(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{}}
	proposed := []prProposedFile{
		{Path: "envs/prod/hpa-a.yaml", Deleted: true},
	}
	held, detail, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !held {
		t.Fatalf("held = false, want true — the file is still deleted, exactly as this pull request left it. detail: %s", detail)
	}
}

// TestCompareProposedFilesAtRevision_DeletedFileReappearedFails: something
// re-added a file this pull request deleted — the merged fix no longer
// holds, and must be reported as such rather than as a pass (the read
// succeeding, which for a WRITE would mean nothing changed, means the exact
// opposite for a DELETE).
func TestCompareProposedFilesAtRevision_DeletedFileReappearedFails(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{
		"envs/prod/hpa-a.yaml": "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n",
	}}
	proposed := []prProposedFile{
		{Path: "envs/prod/hpa-a.yaml", Deleted: true},
	}
	held, detail, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err != nil {
		t.Fatalf("err = %v, want nil — a reappeared file is a verdict, not a failed check", err)
	}
	if held {
		t.Fatal("held = true, want false — the file this pull request deleted exists again")
	}
	if detail == "" {
		t.Error("detail is empty, want an explanation naming the file")
	}
}

// TestCompareProposedFilesAtRevision_ReadErrorIsNotAVerdict: a provider
// failure (network, auth) must surface as an error, exactly like
// syncedPastMergeCommit's own equivalent case — never as held=false, which
// would misreport an inconclusive check as "reverted".
func TestCompareProposedFilesAtRevision_ReadErrorIsNotAVerdict(t *testing.T) {
	p := &fakeReadFileProvider{err: errors.New("github: unreachable")}
	proposed := []prProposedFile{{Path: "envs/prod/deployment.yaml", Content: "replicas: 3\n"}}
	_, _, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{Owner: "acme", Name: "platform-config"}, "c0ffee", proposed)
	if err == nil {
		t.Fatal("want an error when the read itself cannot be made, got nil")
	}
}

// TestCompareProposedFilesAtRevision_StopsAtFirstMismatch: files are checked
// in order and the function returns on the first mismatch rather than
// reading every file regardless — a second file that would also fail need
// not be read to answer "does this hold".
func TestCompareProposedFilesAtRevision_StopsAtFirstMismatch(t *testing.T) {
	p := &fakeReadFileProvider{content: map[string]string{
		"a.yaml": "wrong\n",
	}}
	proposed := []prProposedFile{
		{Path: "a.yaml", Content: "right\n"},
		{Path: "b.yaml", Content: "right\n"},
	}
	held, _, err := compareProposedFilesAtRevision(context.Background(), p, scm.Repo{}, "c0ffee", proposed)
	if err != nil || held {
		t.Fatalf("held=%v err=%v, want false/nil", held, err)
	}
	if len(p.calls) != 1 {
		t.Errorf("ReadFile called %d times, want 1 — b.yaml need not be read once a.yaml already failed", len(p.calls))
	}
}
