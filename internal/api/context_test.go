package api

import "testing"

// TestOnCommitRunsOnlyAfterCommit guards the post-commit hook added to close a
// real bug: handleDecommissionCluster severed a live agent tunnel inline, so a
// commit failure left the tunnel cut while the cluster stayed Active in the
// database — a cluster that looks connected but isn't, recoverable only by
// restarting the agent.
func TestOnCommitRunsOnlyAfterCommit(t *testing.T) {
	t.Run("runs in registration order after a successful commit", func(t *testing.T) {
		rc := &requestContext{}
		var order []string
		rc.OnCommit(func() { order = append(order, "first") })
		rc.OnCommit(func() { order = append(order, "second") })

		if len(order) != 0 {
			t.Fatalf("registering must not execute anything, got %v", order)
		}
		rc.runAfterCommit()
		if len(order) != 2 || order[0] != "first" || order[1] != "second" {
			t.Errorf("hooks ran as %v, want [first second]", order)
		}
	})

	t.Run("no hooks registered is a no-op", func(t *testing.T) {
		rc := &requestContext{}
		rc.runAfterCommit() // must not panic on a nil slice
	})
}
