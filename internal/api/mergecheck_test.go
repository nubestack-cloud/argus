package api

import (
	"context"
	"errors"
	"testing"

	"argus/internal/scm"
)

// fakeIsAncestorProvider satisfies scm.Provider by embedding it as a nil
// interface and overriding only IsAncestor. syncedPastMergeCommit — the only
// thing under test in this file — calls nothing else on the interface, so
// every other method panics on use, which is exactly what a stray call
// deserves here.
type fakeIsAncestorProvider struct {
	scm.Provider
	contains bool
	err      error
	calls    int
}

func (f *fakeIsAncestorProvider) IsAncestor(context.Context, scm.Repo, string, string) (bool, error) {
	f.calls++
	return f.contains, f.err
}

// TestSyncedPastMergeCommit covers BUGS.md 81: CheckPullRequestMerged used to
// require the GitOps controller's reported revision to equal the merge commit
// exactly, which never becomes true again once a later, unrelated commit
// lands on the base branch before the next sync — the reported revision is
// then a genuine descendant of the merge commit, not a mismatch.
func TestSyncedPastMergeCommit(t *testing.T) {
	ctx := context.Background()
	repo := scm.Repo{Owner: "acme", Name: "platform-config"}

	t.Run("no live target — nothing to check yet", func(t *testing.T) {
		p := &fakeIsAncestorProvider{}
		synced, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", nil)
		if err != nil || synced {
			t.Fatalf("synced=%v err=%v, want false/nil", synced, err)
		}
		if p.calls != 0 {
			t.Errorf("IsAncestor called %d times, want 0 — no live revision to ask about", p.calls)
		}
	})

	t.Run("empty reported revision", func(t *testing.T) {
		p := &fakeIsAncestorProvider{}
		synced, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", &incidentRepoTarget{Revision: ""})
		if err != nil || synced {
			t.Fatalf("synced=%v err=%v, want false/nil", synced, err)
		}
		if p.calls != 0 {
			t.Errorf("IsAncestor called %d times, want 0", p.calls)
		}
	})

	t.Run("exact match — the fast path must not pay for a network call", func(t *testing.T) {
		p := &fakeIsAncestorProvider{}
		synced, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", &incidentRepoTarget{Revision: "deadbeef"})
		if err != nil || !synced {
			t.Fatalf("synced=%v err=%v, want true/nil", synced, err)
		}
		if p.calls != 0 {
			t.Errorf("IsAncestor called %d times, want 0 — an exact match must be decided without asking the provider", p.calls)
		}
	})

	t.Run("descendant commit — another PR merged before this one synced (BUGS.md 81's own scenario)", func(t *testing.T) {
		p := &fakeIsAncestorProvider{contains: true}
		synced, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", &incidentRepoTarget{Revision: "c0ffee"})
		if err != nil || !synced {
			t.Fatalf("synced=%v err=%v, want true/nil — c0ffee contains deadbeef even though it is not equal to it", synced, err)
		}
		if p.calls != 1 {
			t.Errorf("IsAncestor called %d times, want exactly 1", p.calls)
		}
	})

	t.Run("genuinely not yet synced", func(t *testing.T) {
		p := &fakeIsAncestorProvider{contains: false}
		synced, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", &incidentRepoTarget{Revision: "stale123"})
		if err != nil || synced {
			t.Fatalf("synced=%v err=%v, want false/nil", synced, err)
		}
	})

	t.Run("the ancestry check itself fails — must be an error, never read as not-synced", func(t *testing.T) {
		p := &fakeIsAncestorProvider{err: errors.New("github: unreachable")}
		_, err := syncedPastMergeCommit(ctx, p, repo, "deadbeef", &incidentRepoTarget{Revision: "c0ffee"})
		if err == nil {
			t.Fatal("want an error when the ancestry check itself cannot be made, got nil — an unreachable provider must never be read as a verdict")
		}
	})
}
