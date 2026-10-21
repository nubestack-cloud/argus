package gitops

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// SUPERSEDED — DO NOT BUILD ON THIS. See REMEDIATION_ROADMAP.md decision D-R5
// (WORKLOG §124).
//
// Cloning is no longer how ARGUS reaches a repository. The product integrates as
// a GitHub App / GitLab application instead: one API request reads a single
// file, and the branch/commit/pull-request are created through the provider API.
// That needs no repository copy on disk, no push credential, and gives the
// customer per-repository grant and revocation — the model Dependabot, Renovate
// and Snyk use. It also deleted two open design problems outright rather than
// solving them: where clones live on a read-only-rootfs hub, and go-git's
// missing partial-clone support.
//
// This file is kept, working and tested, for one contingency only: a customer on
// a bare git host with no usable API. If that case does not appear, delete it
// once the SCMProvider implementation lands (tracked in BACKLOG.md). Its sibling
// locate.go is NOT superseded — it works on any local tree, which is what
// remains after a provider archive fetch for Helm rendering.
//
// Original rationale for go-git over the git binary, still true and still the
// reason a future renderer image (not the hub) is where a git binary would go:
// the hub image is distroless (`gcr.io/distroless/base-debian12`, see
// Dockerfile), so there is no git executable to shell out to, and adding one
// would give up the distroless posture for this one feature.

// CloneOptions is one repository fetch.
type CloneOptions struct {
	// RepoURL must be https. See validateRepoURL.
	RepoURL string
	// Revision is what to check out. A resolved commit SHA is strongly
	// preferred — get_gitops_ownership already reports one, with
	// revision_pinned telling the caller whether it is real (WORKLOG §121) —
	// but a branch or tag is accepted, because a controller that has never
	// synced has no commit to offer.
	Revision string
	// Dir must not already exist; Clone creates it. The caller owns removal.
	Dir string
	// SparsePaths limits what is materialised in the working tree to these
	// repository-relative directories. Strongly recommended: pass the path the
	// GitOps controller itself reports (Argo's `spec.source.path`, a Flux
	// Kustomization's `spec.path`, a Fleet GitRepo's `spec.paths`), all of
	// which get_gitops_ownership already resolves.
	//
	// This is `lld/09` §4's "sparse, shallow clones only ... a monorepo with a
	// hundred unrelated application directories never has more than the
	// relevant subtree materialized". Measured on the small real repo used for
	// the live proof, passing the single relevant directory takes the working
	// tree from 71 YAML files to 2 — and a monorepo is where that ratio stops
	// being a curiosity.
	//
	// Empty materialises the whole tree, which stays correct when the
	// controller reports no path (a repo-root Application).
	SparsePaths []string
	// Token, when set, is used as an HTTP basic-auth password. Empty for a
	// public repository, which is the only case exercised so far — see the
	// credential note below.
	Token string
	// AllowedHosts is an exact-match allowlist of hosts this clone may reach.
	// REQUIRED: an empty list denies everything rather than allowing
	// everything. See validateRepoURL for why that default is inverted from
	// the usual convention.
	AllowedHosts []string
}

// Clone fetches RepoURL at Revision into Dir, shallowly.
//
// # The threat model this is written against
//
// The repository URL is not operator-supplied configuration — it arrives from
// a cluster object (an Argo CD Application's spec.source.repoURL) that a tenant
// may be able to influence, and it reaches this function via a model that also
// reads free-text incident descriptions. So it is treated as untrusted input:
//
//   - **https only.** `ssh://`, `git://` and `file://` are refused. `file://`
//     especially: it would turn "clone the repo this object came from" into an
//     arbitrary local-filesystem read on the hub.
//   - **Exact-match host allowlist, defaulting to deny.** An empty
//     AllowedHosts denies rather than permits. This inversion is deliberate —
//     a config mistake that empties the list should stop clones, not silently
//     authorise every host on the internet.
//   - **No credential in the URL.** Any userinfo in RepoURL is stripped before
//     use, so a URL carrying `https://user:token@host/` cannot smuggle
//     credentials, and the only credential used is the one the caller passed
//     explicitly.
//
// This is a trimmed version of the model in dot-ai's `git-utils.go`, which is
// the most mature code in that project and worth reading in full before this is
// extended (WORKLOG §116). Two of its controls are deliberately NOT replicated
// yet because nothing here needs them: a host-bound GIT_ASKPASS helper (that
// exists to keep a token out of a *subprocess* environment, and go-git has no
// subprocess), and credential scrubbing of returned messages (no credential is
// ever placed where it could appear in one — but that must be re-checked the
// moment Token is used against a real private repo).
//
// # No submodules, and why
//
// Submodules are not initialised. A submodule URL is content of the cloned
// repository, so honouring it would let a repo redirect the fetch to a host the
// allowlist above never approved — the allowlist would check the outer URL and
// nothing would check the inner one.
func Clone(ctx context.Context, opts CloneOptions) (*git.Repository, error) {
	clean, err := validateRepoURL(opts.RepoURL, opts.AllowedHosts)
	if err != nil {
		return nil, err
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("gitops: clone dir is required")
	}
	if _, statErr := os.Stat(opts.Dir); statErr == nil {
		return nil, fmt.Errorf("gitops: clone dir %s already exists", opts.Dir)
	}

	cloneOpts := &git.CloneOptions{
		URL:               clean,
		Depth:             1,
		SingleBranch:      true,
		RecurseSubmodules: git.NoRecurseSubmodules,
		Tags:              git.NoTags,
	}
	if opts.Token != "" {
		// Username is required by the transport but ignored by GitHub/GitLab
		// for token auth; the conventional placeholder is used rather than a
		// real account name so nothing here implies an identity it does not
		// have.
		cloneOpts.Auth = &http.BasicAuth{Username: "argus", Password: opts.Token}
	}

	// A branch or tag can be fetched directly as part of the shallow clone; a
	// raw commit SHA cannot (go-git's ReferenceName must be a ref), so those
	// are handled by cloning the default branch and then resolving.
	rev := strings.TrimSpace(opts.Revision)
	isSHA := looksLikeCommitSHA(rev)
	if rev != "" && !isSHA {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(rev)
	}

	// With sparse paths, clone WITHOUT a checkout and then check out only the
	// wanted directories — go-git exposes sparse checkout on the worktree, not
	// on clone. Note the honest limit: go-git does not implement partial clone
	// (`--filter=blob:none`), which lld/09 §4 also asks for, so this reduces
	// what is WRITTEN to the working tree but not what is FETCHED over the
	// network. Closing that second half needs the git binary, which the
	// renderer image will carry anyway (it needs helm); tracked in BACKLOG.md.
	if len(opts.SparsePaths) > 0 {
		cloneOpts.NoCheckout = true
	}

	repo, err := git.PlainCloneContext(ctx, opts.Dir, false, cloneOpts)
	if err != nil {
		if rev != "" && !isSHA {
			// The revision may be a tag rather than a branch, or the branch
			// name may not exist. Retry once without pinning the ref, so a tag
			// or a mis-typed branch degrades to "the default branch" instead of
			// to no clone at all — the caller still learns which commit it got.
			cloneOpts.ReferenceName = ""
			repo, err = git.PlainCloneContext(ctx, opts.Dir, false, cloneOpts)
		}
		if err != nil {
			return nil, fmt.Errorf("gitops: clone %s: %w", clean, err)
		}
	}

	if len(opts.SparsePaths) > 0 {
		wt, wtErr := repo.Worktree()
		if wtErr != nil {
			return nil, fmt.Errorf("gitops: worktree for sparse checkout: %w", wtErr)
		}
		// The Hash is REQUIRED here, and its absence was a real bug: a
		// CheckoutOptions naming neither a Hash nor a Branch asks go-git to
		// resolve HEAD, and after a NoCheckout clone HEAD is not always
		// resolvable — it depends on whether go-git could determine the remote's
		// default branch, which in turn depends on whether that branch is called
		// what it guesses. So sparse cloning worked against one repository
		// (`master`) and failed against another (`main`) with the opaque
		// "reference not found", and the only live test covering it happened to
		// use the first. Resolving HEAD ourselves and passing the hash removes
		// the guess.
		head, headErr := repo.Head()
		if headErr != nil {
			return nil, fmt.Errorf("gitops: resolve HEAD before sparse checkout: %w", headErr)
		}
		if coErr := wt.Checkout(&git.CheckoutOptions{
			Hash:                      head.Hash(),
			SparseCheckoutDirectories: topLevelSparseDirs(opts.SparsePaths),
		}); coErr != nil {
			return nil, fmt.Errorf("gitops: sparse checkout %v at %s: %w", opts.SparsePaths, head.Hash().String()[:12], coErr)
		}
	}
	return repo, nil
}

// topLevelSparseDirs reduces each requested path to its first segment.
//
// This exists because go-git's SparseCheckoutDirectories matches **top-level
// directories only**, and does so silently. Measured against a real repository:
// asking for `apps/nolimits` checks out **zero files**, while asking for `apps`
// checks out fifteen — including `apps/nolimits/deployment.yaml`.
//
// The silence is what makes it dangerous rather than merely limiting. A nested
// path is exactly what a GitOps controller reports (`spec.source.path` is
// routinely `apps/web` or `envs/prod`), so a caller passing one through got an
// empty working tree and no error — and anything then searching that tree
// concludes the object is not declared in the repository. A wrong answer that
// looks like a finding is worse than a refusal.
//
// The cost of the fix is honest over-fetching: asking for `apps` writes every
// directory under it, not just the one wanted. That is a strict improvement on
// writing nothing, and it does not widen what crosses the network at all —
// go-git has no partial clone, which the comment above already says, so the
// whole repository was always fetched regardless. Callers still scope their
// SEARCH to the full path they asked for, so over-fetching changes what is on
// disk and not what is considered.
func topLevelSparseDirs(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		clean := strings.Trim(strings.TrimSpace(filepath.ToSlash(p)), "/")
		if clean == "" || clean == "." {
			continue
		}
		top := clean
		if i := strings.Index(clean, "/"); i > 0 {
			top = clean[:i]
		}
		if seen[top] {
			continue
		}
		seen[top] = true
		out = append(out, top)
	}
	return out
}

// HeadCommit reports the commit actually checked out, so a caller can record
// what it really read rather than what it asked for. lld/09 §4/§5 require the
// resolved commit and say never HEAD; this is how a caller obtains the former
// after a clone that may have been given only a branch.
func HeadCommit(repo *git.Repository) (string, error) {
	ref, err := repo.Head()
	if err != nil {
		return "", err
	}
	return ref.Hash().String(), nil
}

// validateRepoURL enforces the scheme and host rules, and returns the URL with
// any embedded credentials removed.
func validateRepoURL(raw string, allowedHosts []string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("gitops: repo URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("gitops: repo URL %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("gitops: repo URL scheme %q is refused — only https is allowed (a file:// or ssh:// URL from a cluster object would be an arbitrary read)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("gitops: repo URL %q has no host", raw)
	}
	if len(allowedHosts) == 0 {
		return "", fmt.Errorf("gitops: no allowed repository hosts are configured, so %q is refused — an empty allowlist denies rather than permits", u.Host)
	}
	if !hostAllowed(u.Host, allowedHosts) {
		return "", fmt.Errorf("gitops: repository host %q is not in the allowed list %v", u.Host, allowedHosts)
	}
	// Strip any credentials the URL carried. The only credential used is the
	// one passed explicitly in CloneOptions.Token.
	u.User = nil
	return u.String(), nil
}

// hostAllowed is exact, case-insensitive host[:port] matching. No wildcards and
// no suffix matching: "github.com" must not authorise
// "github.com.attacker.example", which a naive suffix check would allow.
func hostAllowed(host string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(host, strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// looksLikeCommitSHA reports whether rev is a full or abbreviated hex commit
// id. Branch names can be hex-only in principle, so this is a heuristic — but
// it only decides which clone strategy to try first, and the fallback covers a
// wrong guess.
func looksLikeCommitSHA(rev string) bool {
	if len(rev) < 7 || len(rev) > 40 {
		return false
	}
	for _, r := range rev {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
