package api

// This file lets ARGUS find, for itself, which file in a repository defines the
// object an incident is about.
//
// # The gap it closes
//
// handleOpenRepositoryChange has always required the caller to supply filePath,
// and said so explicitly: "ARGUS does not search the repository for the file: it
// changes the one you name". That was an honest limitation and it had a real
// consequence — the whole pull-request route could only be driven by a human who
// ALREADY knew which file and which field to change. The AI contributed the
// diagnosis and none of the fix.
//
// The pieces to close it were all present and just never composed: gitops.Clone
// fetches a repository sparsely at a pinned revision, and gitops.LocateIn walks a
// subdirectory and reports every file whose documents define a given object.
// Composing them is what makes an automated proposal possible at all, because the
// alternative — asking the model for a path — asks it to invent a fact about a
// repository it cannot see, and a plausible-looking wrong path is worse than no
// path.
//
// # Refusing rather than picking
//
// Zero matches and several matches are both refused, with different messages,
// and neither guesses:
//
//   - Zero means the object is not declared in the directory its own GitOps
//     controller reports syncing. That is a real and interesting state — a
//     resource applied by hand, or a chart that renders it — and quietly
//     widening the search to the whole repository would turn "I could not find
//     it here" into "I found something with the same name somewhere else".
//   - Several means the same object is declared in more than one file, and only a
//     human can say which is authoritative. Picking the first would be a coin
//     toss whose outcome is a pull request against the wrong environment.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"argus/internal/gitops"
	"argus/internal/scm"
)

// discoveredFile is a located manifest, plus enough context to explain the
// choice in a pull request body or a refusal.
type discoveredFile struct {
	// Path is repository-relative, ready for gitops.ProposalInput.FilePath.
	Path string
	// DocIndex is which document within the file defines the object.
	DocIndex int
	// FilesScanned is how many YAML files were read to find it — quoted in the
	// audit record, because "we looked at 4 files" and "we looked at 400" are
	// different claims about how confident the single match makes us.
	FilesScanned int
	// IdentitySource is empty for the ordinary case — the object searched for
	// came straight off resolveRepoChangeTarget's live-anchored ObjectRef.
	// BACKLOG.md "still open" #4's fallback (locateObjectFileWithFallback,
	// repository_locate_identity.go) sets this to a short tag naming where the
	// kind/name it searched for instead came from, so a caller can be honest
	// about the difference rather than reporting every discovery the same way
	// — this file was found via free text a rejection message named, not via
	// an identity read off anything that ever existed as a live object.
	IdentitySource string
}

// locateObjectFile clones repoURL sparsely at revision and returns the one file
// under sourceDir that defines object.
//
// The clone is shallow, sparse and thrown away: only sourceDir is fetched, only
// at the pinned revision the GitOps controller reports as synced, and the
// directory is removed before returning. Nothing about this needs to persist, and
// a repository checkout that outlives the request is a credential-adjacent thing
// sitting on disk for no reason.
func locateObjectFile(ctx context.Context, provider scm.Provider, binding scm.Binding, repoURL, revision, sourceDir string, object gitops.ObjectRef) (discoveredFile, error) {
	// A provider that will not hand over a fetch credential cannot be searched.
	// Reported as its own refusal rather than attempted and failed, so the answer
	// to "why must I name the file?" is the real reason.
	cred, ok := provider.(scm.CloneCredentialer)
	if !ok {
		return discoveredFile{}, fmt.Errorf("provider %q cannot supply a credential for a git fetch, so ARGUS cannot search the repository — name the file explicitly", provider.Name())
	}
	if strings.TrimSpace(revision) == "" {
		// The same rule ProposeFieldChange enforces, applied earlier so the
		// refusal names the real problem rather than surfacing as a failed clone:
		// searching a moving branch would find a file whose content is not what
		// is running.
		return discoveredFile{}, fmt.Errorf("no synced commit is recorded for this object, so there is no revision whose content is known to be what is running")
	}

	// A temp PARENT, cloned into a child that does not exist yet: gitops.Clone
	// refuses a directory that is already there (so it can never write into
	// someone else's checkout), and os.MkdirTemp creates the one it returns.
	parent, err := os.MkdirTemp("", "argus-locate-")
	if err != nil {
		return discoveredFile{}, fmt.Errorf("create a working directory: %w", err)
	}
	defer os.RemoveAll(parent)
	dir := filepath.Join(parent, "repo")

	var sparse []string
	if clean := strings.Trim(strings.TrimSpace(sourceDir), "/"); clean != "" && clean != "." {
		sparse = []string{clean}
	}
	if _, err := gitops.Clone(ctx, gitops.CloneOptions{
		RepoURL:     repoURL,
		Revision:    revision,
		Dir:         dir,
		SparsePaths: sparse,
		// The host allowlist is the binding's, not a global one: a repository
		// ARGUS was told about is the only host it may fetch from.
		AllowedHosts: []string{binding.Host},
		Token:        cred.CloneToken(),
	}); err != nil {
		return discoveredFile{}, fmt.Errorf("fetch %s at %s: %w", repoURL, shortRevision(revision), err)
	}

	res, err := gitops.LocateIn(dir, sourceDir, object)
	if err != nil {
		return discoveredFile{}, fmt.Errorf("search %s for %s %s/%s: %w", repoURL, object.Kind, object.Namespace, object.Name, err)
	}

	where := sourceDir
	if where == "" {
		where = "the repository root"
	}
	switch len(res.Locations) {
	case 1:
		return discoveredFile{
			Path:         res.Locations[0].Path,
			DocIndex:     res.Locations[0].DocIndex,
			FilesScanned: res.FilesScanned,
		}, nil
	case 0:
		return discoveredFile{}, fmt.Errorf("%s %s/%s is not declared in %s at %s — %d YAML file(s) were read and none defines it. "+
			"That usually means it is rendered by a chart or an overlay rather than written out, or it was applied by hand. "+
			"Name the file explicitly if you know it",
			object.Kind, object.Namespace, object.Name, where, shortRevision(revision), res.FilesScanned)
	default:
		paths := make([]string, 0, len(res.Locations))
		for _, l := range res.Locations {
			paths = append(paths, l.Path)
		}
		return discoveredFile{}, fmt.Errorf("%s %s/%s is declared in %d files under %s (%s) — only you can say which one is authoritative, so name it explicitly rather than having ARGUS pick",
			object.Kind, object.Namespace, object.Name, len(res.Locations), where, strings.Join(paths, ", "))
	}
}

// shortRevision trims a commit for a message without losing its identity.
func shortRevision(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
