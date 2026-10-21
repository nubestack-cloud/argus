package scm

import (
	"strings"
	"testing"
)

// ParseRepoURL is a security boundary, not a convenience: the URL arrives from
// a CLUSTER OBJECT (an Argo Application's spec.source.repoURL) that a tenant may
// influence, and reaches here via a model that also reads free-text incident
// text.
func TestParseRepoURLRefusesDangerousInput(t *testing.T) {
	cases := map[string]string{
		"file:// would be an arbitrary local read on the hub":   "file:///etc/passwd",
		"ssh is not the transport this uses":                    "ssh://git@github.com/a/b.git",
		"git:// is unauthenticated and unencrypted":             "git://github.com/a/b.git",
		"plain http downgrades the transport":                   "http://github.com/a/b.git",
		"embedded credentials mean something upstream is wrong": "https://user:token@github.com/a/b.git",
		"no host":       "https:///a/b",
		"no repo path":  "https://github.com/",
		"only an owner": "https://github.com/acme",
		"empty":         "",
	}
	for why, raw := range cases {
		if _, _, err := ParseRepoURL(raw); err == nil {
			t.Errorf("accepted %q — %s", raw, why)
		}
	}
}

func TestParseRepoURLAcceptsRealShapes(t *testing.T) {
	cases := []struct {
		raw               string
		owner, name, host string
	}{
		{"https://github.com/argoproj/argocd-example-apps.git", "argoproj", "argocd-example-apps", "github.com"},
		{"https://github.com/argoproj/argocd-example-apps", "argoproj", "argocd-example-apps", "github.com"},
		{"https://ghe.internal.example/platform/config.git", "platform", "config", "ghe.internal.example"},
		// A GitLab subgroup path must survive rather than being truncated to
		// the last two segments — otherwise the project is simply wrong.
		{"https://gitlab.example/group/subgroup/project.git", "group/subgroup", "project", "gitlab.example"},
		{"  https://github.com/a/b.git  ", "a", "b", "github.com"},
	}
	for _, tc := range cases {
		repo, host, err := ParseRepoURL(tc.raw)
		if err != nil {
			t.Errorf("%s: %v", tc.raw, err)
			continue
		}
		if repo.Owner != tc.owner || repo.Name != tc.name || host != tc.host {
			t.Errorf("%s -> %s/%s @ %s, want %s/%s @ %s", tc.raw, repo.Owner, repo.Name, host, tc.owner, tc.name, tc.host)
		}
	}
}

// Exact matching only. A suffix check would let github.com authorise
// github.com.attacker.example, which is the classic version of this bug.
func TestMatchesHostIsExact(t *testing.T) {
	if !MatchesHost("GitHub.com", "github.com") {
		t.Error("host comparison should be case-insensitive")
	}
	for _, evil := range []string{"github.com.attacker.example", "notgithub.com", "evil-github.com", "github.co"} {
		if MatchesHost(evil, "github.com") {
			t.Errorf("%q was accepted as github.com", evil)
		}
	}
}

// A credential that can never be used must never be stored. This regressed
// once already: SaveBinding accepted "gitlab" while ProviderFor refused it, so
// registering a GitLab repository returned 201 with credentialStored:true and
// sealed a token whose only possible future was to fail at the first pull
// request — after living in the database and every backup in the meantime.
// BACKLOG.md F15 closed that gap by shipping a real GitLab implementation
// (gitlab.go), so both names below are now accepted, symmetrically.
func TestOnlyImplementedProvidersAreAccepted(t *testing.T) {
	if err := checkProviderImplemented("github"); err != nil {
		t.Fatalf("github refused: %v", err)
	}
	if err := checkProviderImplemented("gitlab"); err != nil {
		t.Fatalf("gitlab refused: %v — F15 shipped a real implementation, this must be accepted like github", err)
	}

	err := checkProviderImplemented("bitbucket")
	if err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	if strings.Contains(err.Error(), "cannot be used yet") {
		t.Errorf("unknown provider refusal reads %q, want it to read as unknown rather than as a roadmap item", err)
	}

	// Every name this build claims to implement must have a constructor in
	// ProviderFor's switch. Without this, adding a name to the map is enough to
	// return a nil provider to a caller that will dereference it.
	for name := range implementedProviders {
		if name != "github" && name != "gitlab" {
			t.Errorf("implementedProviders lists %q, but ProviderFor's switch only constructs github and gitlab — add the case or remove the name", name)
		}
	}
}

// The roadmap-item vs typo distinction (checkProviderImplemented's
// designedProviders branch) still has to work correctly even though it is
// currently empty — the NEXT provider this design grows needs it to behave
// right on day one, not be debugged then.
func TestDesignedButUnimplementedProviderReadsAsRoadmapNotTypo(t *testing.T) {
	designedProviders["bitbucket"] = "test-only: pretend this is a designed-but-unbuilt provider"
	defer delete(designedProviders, "bitbucket")

	err := checkProviderImplemented("bitbucket")
	if err == nil {
		t.Fatal("a designed-but-unimplemented provider was accepted")
	}
	if !strings.Contains(err.Error(), "cannot be used yet") {
		t.Errorf("refusal reads %q, want it to say the provider is designed but unimplemented rather than unknown", err)
	}

	err = checkProviderImplemented("made-up-provider")
	if strings.Contains(err.Error(), "cannot be used yet") {
		t.Errorf("a genuinely unknown provider read as a roadmap item: %v", err)
	}
}

// The five URL forms a real installation actually produces must all resolve to
// one identity. This is the test for the bug that made the whole pull-request
// path unreachable: ProviderFor matched `WHERE b.url = $1` against a string a
// GitOps controller wrote and a string an operator typed, and four of these five
// did not match — each failing as "no binding, register it", which pointed at an
// action already taken.
func TestOneRepositoryHasOneIdentityAcrossEveryURLForm(t *testing.T) {
	registered := "https://github.com/Example-Org/platform-config.git"
	repo, host, err := ParseRepoURL(registered)
	if err != nil {
		t.Fatalf("registered form rejected: %v", err)
	}
	want := RepoKey(host, repo)

	for _, form := range []struct{ name, url string }{
		{"exactly as registered", "https://github.com/Example-Org/platform-config.git"},
		{"no .git suffix", "https://github.com/Example-Org/platform-config"},
		{"trailing slash", "https://github.com/Example-Org/platform-config.git/"},
		{"differently cased host", "https://GitHub.com/Example-Org/platform-config.git"},
		{"differently cased owner", "https://github.com/example-org/platform-config.git"},
		{"scp-like ssh remote", "git@github.com:Example-Org/platform-config.git"},
		{"ssh:// URL", "ssh://git@github.com/Example-Org/platform-config.git"},
		{"ssh:// URL with a port", "ssh://git@github.com:22/Example-Org/platform-config.git"},
	} {
		t.Run(form.name, func(t *testing.T) {
			r, h, err := ParseRepoRef(form.url)
			if err != nil {
				t.Fatalf("ParseRepoRef(%q) = %v, want it to resolve to the same repository as the registered form", form.url, err)
			}
			if got := RepoKey(h, r); got != want {
				t.Errorf("ParseRepoRef(%q) -> key %q, want %q — a binding lookup would miss and the operator would be told to register a repository they already registered", form.url, got, want)
			}
		})
	}
}

// Two genuinely different repositories must not collapse into one identity. The
// normalisation above is deliberately lossy (it lowercases), so this is the
// other half of that trade-off and the thing that would make it unsafe.
func TestDifferentRepositoriesKeepDifferentIdentities(t *testing.T) {
	base, baseHost, err := ParseRepoRef("https://github.com/org/platform-config")
	if err != nil {
		t.Fatal(err)
	}
	baseKey := RepoKey(baseHost, base)

	for _, other := range []string{
		"https://github.com/other-org/platform-config", // different owner
		"https://github.com/org/platform-configs",      // different name
		"https://gitlab.example/org/platform-config",   // different host
		"https://github.com/org/sub/platform-config",   // subgroup path, not the same project
	} {
		r, h, err := ParseRepoRef(other)
		if err != nil {
			t.Fatalf("ParseRepoRef(%q): %v", other, err)
		}
		if got := RepoKey(h, r); got == baseKey {
			t.Errorf("ParseRepoRef(%q) collapsed onto %q — a credential for one repository would be used against another", other, baseKey)
		}
	}
}

// ParseRepoRef widened what is ACCEPTED, so what it still refuses is the part
// worth pinning down. It is used only for matching, never for transport, but a
// value that reaches it can still come from a tenant-influenced cluster object.
func TestParseRepoRefStillRefusesWhatItMust(t *testing.T) {
	for _, tc := range []struct{ name, url, wantIn string }{
		{"file scheme", "file:///etc/shadow", "refused"},
		{"git scheme", "git://github.com/org/repo.git", "refused"},
		{"http scheme", "http://github.com/org/repo.git", "refused"},
		{"password in an https URL", "https://user:secret@github.com/org/repo.git", "password"},
		{"password in an scp-like URL", "user:secret@github.com:org/repo.git", "password"},
		{"no owner", "https://github.com/repo", "owner/name"},
		{"empty", "   ", "required"},
		{"not a repository URL at all", "just-some-text", "cannot read a repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseRepoRef(tc.url)
			if err == nil {
				t.Fatalf("ParseRepoRef(%q) was accepted", tc.url)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("ParseRepoRef(%q) = %v, want a message containing %q", tc.url, err, tc.wantIn)
			}
		})
	}
}
