package scm

import (
	"path"
	"strings"
)

// Write scope: which paths in a registered repository ARGUS may commit to.
//
// # Why this is a denylist AND why a denylist is not the control
//
// DESIGN.md §11.1 is unusually explicit that a path denylist alone "is not
// sufficient", and it is worth restating the reason rather than leaving a reader
// to assume this file is the whole answer: **an AI agent that can edit
// `.gitlab-ci.yml` can run arbitrary code in the customer's CI with the CI's
// credentials.** §11.1 calls that the highest-severity privilege-escalation path
// in the product. A denylist misses GitLab's configurable custom CI config path,
// `include:`-referenced fragments living anywhere, `Makefile`/`Dockerfile`/
// `scripts/**` invoked *by* CI, `.pre-commit-config.yaml`, Kustomize
// `generators:`/`transformers:` and exec/KRM plugins, and a `Chart.yaml` edit
// that repoints a chart at an attacker-controlled registry.
//
// So the actual control is §11.1's allowlist shape, and it is enforced by the
// caller, not here:
//
//  1. ARGUS may only write inside the source directory registered for the
//     object's binding, and every proposed file is checked against that
//     confinement and against this denylist before any network call
//     (`gitops.prepareChanges`). Templated sources — Helm, Kustomize — are
//     editable: a repository change is a set of whole files, and the claim
//     ARGUS makes about them is that they are in scope, not that the edit is
//     minimal. What makes a whole-file edit safe to merge is the human
//     reading the rendered diff; see DESIGN.md §11.4 for why the older
//     minimality proof was removed rather than extended.
//  2. This file is §11.1's point 2: the "belt-and-braces denylist,
//     non-overridable, and additionally covers the surface above."
//
// Read in that order, the two are complementary rather than redundant: the
// allowlist decides what MAY be written, and this decides what may never be,
// whatever the allowlist concluded.

// WriteScope is a binding's `spec.writeScope` (DESIGN.md §11.1), as stored by
// SaveBinding.
//
// Only ForbiddenPaths is read today. §11.1's `allowedPaths` is deliberately not
// implemented as a stored field: the effective allowlist in this build is
// narrower than any pattern an operator could write — one plain-YAML file that
// has been proven to define the live object being fixed — so honouring a broad
// stored `allowedPaths` would only ever *widen* an operator's expectation of what
// ARGUS can touch, never narrow what it actually does.
type WriteScope struct {
	ForbiddenPaths []string
}

// builtinForbiddenPaths is the non-overridable half of the denylist.
//
// Non-overridable is the point: these are not defaults an operator may relax by
// rewriting a binding's spec, because every one of them is a path where a write
// converts "ARGUS may propose a manifest change" into "ARGUS may execute code in
// your CI" or "ARGUS may silently repoint your images". `SaveBinding` writes a
// subset of these into the binding's own spec for visibility; the list here is
// what is actually enforced, so a spec edited by hand — or a future UI that lets
// an operator prune the stored list — cannot open the hole.
//
// `*.age`, `*.sops.*` and sealed secrets are here for a different reason, per
// §11.4: ARGUS must not touch content it cannot read. A "minimal edit" to an
// encrypted file is not minimal, it is corruption.
var builtinForbiddenPaths = []string{
	// CI definitions and everything that configures them. `**/` variants
	// included because GitLab's CI config path is configurable and GitHub Actions
	// composite actions can live anywhere.
	".github/**",
	"**/.github/**",
	".gitlab-ci.yml",
	"**/.gitlab-ci.yml",
	".gitlab/**",
	".pre-commit-config.yaml",
	"**/.pre-commit-config.yaml",
	"Jenkinsfile",
	"**/Jenkinsfile",
	"azure-pipelines.yml",
	"**/azure-pipelines.yml",
	// Things CI invokes. Editing these is editing the pipeline by proxy.
	"Dockerfile",
	"**/Dockerfile",
	"Makefile",
	"**/Makefile",
	"scripts/**",
	"**/*.sh",
	// Encrypted content ARGUS cannot read, so cannot minimally edit.
	"**/*.sops.yaml",
	"**/*.sops.yml",
	"**/*.enc.yaml",
	"**/*.enc.yml",
	"**/*.age",
	"**/sealed-secret*.yaml",
	"**/sealed-secret*.yml",
	"**/secrets/**",
	// Chart metadata and Kustomize entry points: §11.1's registry-repointing and
	// exec/KRM-plugin surfaces. `internal/gitops` refuses these earlier with a
	// message about rendering; they are here too because the reason they must not
	// be written is a security one, not only a "we cannot verify it" one.
	"Chart.yaml",
	"**/Chart.yaml",
	"**/Chart.lock",
	"kustomization.yaml",
	"**/kustomization.yaml",
	"kustomization.yml",
	"**/kustomization.yml",
	"**/Kustomization",
	// Argo CD's own per-directory parameter overrides: a write here changes how
	// Argo renders, which is a change ARGUS cannot verify by reading YAML.
	"**/.argocd-source*.yaml",
}

// ForbiddenPath returns the pattern that forbids writing to p, or "" if none
// does. `extra` is the binding's own stored `spec.writeScope.forbiddenPaths`,
// checked in addition to — never instead of — builtinForbiddenPaths.
//
// A path that cannot be normalised (absolute, empty, or containing a `..`
// segment) is refused by returning a sentinel pattern rather than being cleaned
// up: the path originates in a request that names a file to commit to, and
// silently rewriting a traversal attempt into something valid would hide it.
func ForbiddenPath(p string, extra []string) string {
	clean, ok := normalizeRepoPath(p)
	if !ok {
		return "<not a repository-relative path>"
	}
	for _, pattern := range builtinForbiddenPaths {
		if matchRepoPath(pattern, clean) {
			return pattern
		}
	}
	for _, pattern := range extra {
		if matchRepoPath(strings.TrimSpace(pattern), clean) {
			return pattern
		}
	}
	return ""
}

// normalizeRepoPath turns a repository-relative path into forward-slash,
// no-leading-slash, no-`..` form. Returns false rather than a best effort when
// the input is not one — see ForbiddenPath.
func normalizeRepoPath(p string) (string, bool) {
	s := strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if s == "" || strings.HasPrefix(s, "/") {
		return "", false
	}
	// path.Clean collapses "a/./b" and "a//b" but would also silently resolve
	// "a/../b"; the segment scan below runs on the CLEANED value so that a `..`
	// which Clean could not remove (a leading one) is still caught, and on the
	// raw value so that "a/../b" is refused rather than quietly becoming "b".
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return "", false
		}
	}
	cleaned := path.Clean(s)
	if cleaned == "." || strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	return cleaned, true
}

// matchRepoPath is glob matching with `**` meaning "any number of path
// segments, including none".
//
// path.Match alone is not enough: it treats `*` as "anything but a separator"
// and has no `**` at all, so `**/*.sops.yaml` — a pattern DESIGN.md §11.1 writes
// literally — would match nothing. Implemented segment-wise rather than by
// translating to a regexp because the recursion is short, obvious, and cannot
// accidentally admit a pattern that matches across separators.
//
// Deliberately NOT suffix matching. The same reasoning as MatchesHost: a rule
// that "ends with .sops.yaml" is a different claim from "this path segment is a
// file called something.sops.yaml", and the loose version is the one that
// eventually waves something through.
func matchRepoPath(pattern, p string) bool {
	if pattern == "" {
		return false
	}
	pat, ok := normalizeRepoPath(pattern)
	if !ok {
		// A pattern like "/etc/**" or "" cannot describe a repository-relative
		// path, so it matches nothing rather than everything.
		return false
	}
	return matchSegments(strings.Split(pat, "/"), strings.Split(p, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// Trailing `**` matches the rest, including nothing — so
			// ".github/**" covers ".github" itself as well as its contents.
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// WithinRepoDir reports whether file sits inside dir (both
// repository-relative). An empty dir means the repository root, which contains
// everything.
//
// This is how a request-supplied file path is confined to the directory the
// GitOps controller itself reports syncing (`spec.source.path`): the same
// containment rule LocateIn applies to a controller-reported subdir, applied in
// the other direction. Without it, an incident whose Argo Application syncs
// `envs/dev` could be used to open a pull request against `envs/prod`.
func WithinRepoDir(dir, file string) bool {
	cleanFile, ok := normalizeRepoPath(file)
	if !ok {
		return false
	}
	d := strings.Trim(strings.TrimSpace(strings.ReplaceAll(dir, "\\", "/")), "/")
	if d == "" || d == "." {
		return true
	}
	cleanDir, ok := normalizeRepoPath(d)
	if !ok {
		return false
	}
	return cleanFile == cleanDir || strings.HasPrefix(cleanFile, cleanDir+"/")
}
