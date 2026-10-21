package scm

import (
	"strings"
	"testing"
)

// The non-overridable list is the one that matters: every entry in it is a path
// where a write turns "ARGUS may propose a manifest change" into "ARGUS may run
// code in your CI" (DESIGN.md §11.1) or "ARGUS may corrupt content it cannot
// read" (§11.4).
func TestForbiddenPath_BuiltinList(t *testing.T) {
	forbidden := []string{
		".github/workflows/deploy.yml",
		".github/workflows/nested/deploy.yml",
		"tools/.github/workflows/deploy.yml",
		".gitlab-ci.yml",
		"ci/.gitlab-ci.yml",
		".gitlab/agents/x.yaml",
		".pre-commit-config.yaml",
		"Jenkinsfile",
		"Dockerfile",
		"apps/web/Dockerfile",
		"Makefile",
		"scripts/deploy.py",
		"scripts/nested/deploy.py",
		"hack/build.sh",
		"envs/prod/db.sops.yaml",
		"db.sops.yaml",
		"envs/prod/db.enc.yml",
		"keys/master.age",
		"envs/prod/sealed-secret-db.yaml",
		"secrets/token.yaml",
		"envs/prod/secrets/token.yaml",
		"Chart.yaml",
		"charts/app/Chart.yaml",
		"charts/app/Chart.lock",
		"kustomization.yaml",
		"envs/prod/kustomization.yml",
		"envs/prod/Kustomization",
		"envs/prod/.argocd-source-shop.yaml",
	}
	for _, p := range forbidden {
		if got := ForbiddenPath(p, nil); got == "" {
			t.Errorf("%s is ALLOWED — it must not be", p)
		}
	}

	allowed := []string{
		"envs/prod/deployment.yaml",
		"envs/prod/checkout/deployment.yaml",
		"manifests/web.yml",
		// Near-misses for the patterns above. A loose suffix or substring rule
		// would wave several of these through as forbidden, which is its own bug:
		// refusing a legitimate manifest is a silent loss of the whole feature.
		"envs/prod/not-a-dockerfile.yaml",
		"envs/prod/sops-notes.yaml",
		"envs/prod/kustomize-notes.yaml",
		"envs/production/deployment.yaml",
		"github-app/deployment.yaml",
	}
	for _, p := range allowed {
		if got := ForbiddenPath(p, nil); got != "" {
			t.Errorf("%s is forbidden by %q — it should be editable", p, got)
		}
	}
}

// The binding's own patterns are additive: they can add rules, never remove the
// built-in ones.
func TestForbiddenPath_BindingPatternsAreAdditive(t *testing.T) {
	extra := []string{"envs/prod/frozen-*.yaml", "legacy/**"}
	if got := ForbiddenPath("envs/prod/frozen-app.yaml", extra); got != "envs/prod/frozen-*.yaml" {
		t.Errorf("binding pattern not applied: got %q", got)
	}
	if got := ForbiddenPath("legacy/a/b/c.yaml", extra); got != "legacy/**" {
		t.Errorf("binding ** pattern not applied: got %q", got)
	}
	// A binding whose stored list is empty (or that names only harmless things)
	// still cannot make a CI definition writable.
	if got := ForbiddenPath(".github/workflows/x.yml", []string{"nothing/**"}); got == "" {
		t.Error("an empty-ish binding list disabled the built-in denylist")
	}
}

// A path that is not repository-relative is refused rather than cleaned up: it
// arrives in a request naming a file to commit to, and silently rewriting a
// traversal attempt would hide it.
func TestForbiddenPath_RefusesPathsThatAreNotRepositoryRelative(t *testing.T) {
	for _, p := range []string{
		"", "   ", "/etc/passwd", "../outside.yaml", "envs/../../etc/passwd",
		"envs/prod/../../../x.yaml", "..",
	} {
		got := ForbiddenPath(p, nil)
		if got == "" {
			t.Errorf("%q was ALLOWED", p)
		}
		if !strings.Contains(got, "repository-relative") {
			t.Errorf("%q was refused by %q rather than as a bad path", p, got)
		}
	}
}

// `a/../b` must not quietly become `b`: a pattern-matching pass on the cleaned
// value would then authorise a path the caller never wrote.
func TestForbiddenPath_DoesNotResolveDotDotIntoAnAllowedPath(t *testing.T) {
	if got := ForbiddenPath("envs/prod/../.github/workflows/x.yml", nil); !strings.Contains(got, "repository-relative") {
		t.Errorf("a traversal into .github was handled as %q", got)
	}
}

func TestWithinRepoDir(t *testing.T) {
	cases := []struct {
		dir, file string
		want      bool
	}{
		{"envs/prod", "envs/prod/deployment.yaml", true},
		{"envs/prod", "envs/prod/web/deployment.yaml", true},
		{"envs/prod/", "envs/prod/deployment.yaml", true},
		{"/envs/prod", "envs/prod/deployment.yaml", true},
		{"", "anything/at/all.yaml", true},
		{".", "anything/at/all.yaml", true},
		{"envs/prod", "envs/staging/deployment.yaml", false},
		// The prefix trap: "envs/production" starts with "envs/prod" as a STRING
		// but is a different directory, and a naive HasPrefix check would let an
		// incident about envs/prod open a pull request against it.
		{"envs/prod", "envs/production/deployment.yaml", false},
		{"envs/prod", "deployment.yaml", false},
		{"envs/prod", "../envs/prod/deployment.yaml", false},
		{"envs/prod", "/envs/prod/deployment.yaml", false},
	}
	for _, tc := range cases {
		if got := WithinRepoDir(tc.dir, tc.file); got != tc.want {
			t.Errorf("WithinRepoDir(%q, %q) = %v, want %v", tc.dir, tc.file, got, tc.want)
		}
	}
}

// The spec column is DESIGN.md §11.3's contract, so the decode has to survive
// both what SaveBinding writes today and a binding row that predates it.
func TestApplySpec(t *testing.T) {
	t.Run("what SaveBinding writes", func(t *testing.T) {
		raw := []byte(`{"fixBranch":{"strategy":"newBranch","pattern":"argus/fix-{incidentId}"},
		                "pullRequest":{"enabled":true},
		                "writeScope":{"forbiddenPaths":[".github/workflows/**","**/*.sops.yaml"]}}`)
		var b Binding
		if err := applySpec(&b, raw); err != nil {
			t.Fatal(err)
		}
		if b.FixBranchPattern != "argus/fix-{incidentId}" {
			t.Errorf("FixBranchPattern = %q", b.FixBranchPattern)
		}
		if !b.PullRequestEnabled {
			t.Error("pull requests read as disabled")
		}
		if len(b.WriteScope.ForbiddenPaths) != 2 {
			t.Errorf("ForbiddenPaths = %v", b.WriteScope.ForbiddenPaths)
		}
	})

	t.Run("a binding with no spec at all", func(t *testing.T) {
		var b Binding
		if err := applySpec(&b, nil); err != nil {
			t.Fatal(err)
		}
		// Absent must not read as disabled: a binding registered with no spec was
		// registered in order to open pull requests, and defaulting to off would
		// make the feature silently unavailable.
		if !b.PullRequestEnabled {
			t.Error("an absent spec disabled pull requests")
		}
	})

	t.Run("explicitly disabled", func(t *testing.T) {
		var b Binding
		if err := applySpec(&b, []byte(`{"pullRequest":{"enabled":false}}`)); err != nil {
			t.Fatal(err)
		}
		if b.PullRequestEnabled {
			t.Error("an explicit false was ignored")
		}
	})

	t.Run("a spec that does not parse", func(t *testing.T) {
		var b Binding
		if err := applySpec(&b, []byte(`{not json`)); err == nil {
			t.Fatal("an unreadable write policy was accepted")
		}
		if b.PullRequestEnabled {
			t.Error("an unreadable spec left pull requests enabled")
		}
	})
}
