package gitops

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRepoURL_RefusesNonHTTPS: the repo URL arrives from a cluster
// object a tenant may influence, so file:// would be an arbitrary local read
// on the hub and ssh:// would reach hosts the allowlist never approved.
func TestValidateRepoURL_RefusesNonHTTPS(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/shadow",
		"ssh://git@github.com/org/repo.git",
		"git://github.com/org/repo.git",
		"http://github.com/org/repo.git",
	} {
		if _, err := validateRepoURL(raw, []string{"github.com"}); err == nil {
			t.Errorf("validateRepoURL(%q) = nil error, want a refusal", raw)
		}
	}
}

// TestValidateRepoURL_EmptyAllowlistDenies pins the inverted default: a config
// mistake that empties the list must stop clones, not silently authorise every
// host on the internet.
func TestValidateRepoURL_EmptyAllowlistDenies(t *testing.T) {
	if _, err := validateRepoURL("https://github.com/org/repo.git", nil); err == nil {
		t.Error("an empty allowlist must deny, not permit everything")
	}
}

// TestValidateRepoURL_NoSuffixMatching: a naive suffix check would let
// "github.com" authorise "github.com.attacker.example".
func TestValidateRepoURL_NoSuffixMatching(t *testing.T) {
	if _, err := validateRepoURL("https://github.com.attacker.example/org/repo.git", []string{"github.com"}); err == nil {
		t.Error("host matching must be exact — a lookalike domain must not be authorised by a suffix match")
	}
	if _, err := validateRepoURL("https://notgithub.com/org/repo.git", []string{"github.com"}); err == nil {
		t.Error("a different host must not be authorised")
	}
}

// TestValidateRepoURL_StripsEmbeddedCredentials: a URL carrying userinfo must
// not be able to smuggle a credential past the explicit Token parameter.
func TestValidateRepoURL_StripsEmbeddedCredentials(t *testing.T) {
	clean, err := validateRepoURL("https://someone:secrettoken@github.com/org/repo.git", []string{"github.com"})
	if err != nil {
		t.Fatalf("validateRepoURL: %v", err)
	}
	if strings.Contains(clean, "secrettoken") || strings.Contains(clean, "someone") {
		t.Errorf("cleaned URL still carries credentials: %q", clean)
	}
	if clean != "https://github.com/org/repo.git" {
		t.Errorf("clean = %q", clean)
	}
}

func TestValidateRepoURL_AllowsListedHostCaseInsensitively(t *testing.T) {
	if _, err := validateRepoURL("https://GitHub.com/org/repo.git", []string{"github.com"}); err != nil {
		t.Errorf("host matching should be case-insensitive: %v", err)
	}
}

func TestLooksLikeCommitSHA(t *testing.T) {
	sha := "8088f4c0d970abb09e250248cc97e35623447cb5" // the real revision from WORKLOG §121
	if !looksLikeCommitSHA(sha) {
		t.Errorf("a real 40-char commit id should be recognised")
	}
	for _, notSHA := range []string{"main", "HEAD", "v1.2.3", "release/2024", "", "abc"} {
		if looksLikeCommitSHA(notSHA) {
			t.Errorf("looksLikeCommitSHA(%q) = true, want false", notSHA)
		}
	}
}

// Clone must refuse an existing directory rather than clone into a tree that
// already has content — a silent merge would make "what did we read" unanswerable.
func TestClone_RefusesExistingDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Clone(t.Context(), CloneOptions{
		RepoURL: "https://github.com/org/repo.git", Dir: dir, AllowedHosts: []string{"github.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v, want a refusal that the dir exists", err)
	}
}

// TestClone_ValidatesBeforeTouchingTheNetwork: a refused URL must fail on the
// rule, not after a DNS lookup or a connection attempt.
func TestClone_ValidatesBeforeTouchingTheNetwork(t *testing.T) {
	_, err := Clone(t.Context(), CloneOptions{
		RepoURL: "file:///etc", Dir: filepath.Join(t.TempDir(), "x"), AllowedHosts: []string{"github.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "only https") {
		t.Errorf("err = %v, want the scheme refusal", err)
	}
}

// TestCloneOptions_SparsePathsAreOptional: an empty SparsePaths must still be a
// valid whole-tree clone, which is correct for a repo-root Application where the
// controller reports no path.
func TestCloneOptions_SparsePathsAreOptional(t *testing.T) {
	// Validation must not reject the no-sparse case before any network work.
	if _, err := validateRepoURL("https://github.com/org/repo.git", []string{"github.com"}); err != nil {
		t.Fatalf("a plain whole-tree clone URL must validate: %v", err)
	}
}

// TestTopLevelSparseDirs covers the reduction that makes a nested sparse path
// work at all. go-git's SparseCheckoutDirectories matches only top-level
// directories and says nothing when given something deeper — measured on a real
// repository, `apps/nolimits` checked out zero files while `apps` checked out
// fifteen. A caller passing a GitOps controller's own `spec.source.path`
// (routinely nested) therefore got an empty tree and no error.
func TestTopLevelSparseDirs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"nested path reduces to its root", []string{"apps/nolimits"}, []string{"apps"}},
		{"deeply nested", []string{"envs/prod/eu-west-1"}, []string{"envs"}},
		{"already top level", []string{"apps"}, []string{"apps"}},
		{"two paths sharing a root are deduplicated", []string{"apps/web", "apps/api"}, []string{"apps"}},
		{"distinct roots are both kept", []string{"apps/web", "charts/cache"}, []string{"apps", "charts"}},
		{"leading and trailing slashes", []string{"/apps/web/"}, []string{"apps"}},
		// A repository root request must not become the empty string, which
		// go-git would treat as a directory name.
		{"dot and empty are dropped", []string{".", "", "   "}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := topLevelSparseDirs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("topLevelSparseDirs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("topLevelSparseDirs(%v)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}
