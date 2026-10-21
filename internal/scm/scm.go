// Package scm is ARGUS's Git-provider abstraction: read a file, branch, commit,
// open a pull request — over the provider's REST API, with no local clone.
//
// # What this is NOT, and why
//
// `lld/09` §3 originally specified `Clone / CreateBranch / Commit / Push`. That
// is superseded by `REMEDIATION_ROADMAP.md` **D-R5**: no cloning and no pushing.
// The interface below reads one file through the Contents API and creates the
// branch, the commit and the PR through the API too. That buys a narrower
// credential (no push scope), no scratch filesystem to manage on a
// read-only-rootfs hub, and per-repository grant and revocation by the customer
// — and it deleted two open design problems outright rather than solving them.
//
// `internal/gitops/clone.go` remains, marked superseded, for a hypothetical
// bare-git-host customer.
//
// # Why the interface is shaped for two providers from day one
//
// D-R6's stated worry is that this ends up *"quietly GitHub-shaped"* — the
// failure dot-ai demonstrates, where PR support is github.com-only and
// everything else degrades to `pushed_without_pr`. D-R9 then removed the biggest
// source of that skew by dropping the GitHub App: **both providers now
// authenticate with one scoped token**, so the credential model is symmetric by
// construction rather than by discipline.
//
// The remaining asymmetries are real and belong in the implementations, not
// here: GitHub addresses repositories as `owner/name` while GitLab uses a
// URL-encoded numeric-or-path project id, and GitLab's file API takes a single
// call where GitHub's commit path needs several.
package scm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Provider is one Git host. Implementations must be safe for concurrent use.
//
// Every method takes a Repo rather than a bare URL string, because resolving a
// clone URL to a provider-specific identifier is exactly the kind of parsing
// that should happen once, at the edge, and not be repeated in five methods with
// five slightly different bugs.
type Provider interface {
	// Name is for logs and PR bodies, e.g. "github".
	Name() string

	// ReadFile returns one file's bytes at ref (a branch, tag or commit SHA).
	// ErrNotFound when the path does not exist at that ref — a normal outcome
	// when locating a manifest, not an exception.
	ReadFile(ctx context.Context, repo Repo, ref, path string) ([]byte, error)

	// DefaultBranch is needed because a repository's default is not always
	// `main`, and branching from the wrong base produces a PR full of unrelated
	// changes.
	DefaultBranch(ctx context.Context, repo Repo) (string, error)

	// CreateBranch points a new ref at fromSHA. ErrAlreadyExists if the branch
	// is there — surfaced rather than swallowed, because silently reusing a
	// branch would let two incidents write conflicting commits to one PR.
	CreateBranch(ctx context.Context, repo Repo, branch, fromSHA string) error

	// ResolveRef turns a branch/tag/SHA into a commit SHA. Needed before
	// branching, and separately useful: it is how a caller pins what it read.
	ResolveRef(ctx context.Context, repo Repo, ref string) (string, error)

	// PutFile commits new content for one path on a branch.
	//
	// baseSHA is the blob/file SHA the caller read, and it is REQUIRED: it makes
	// the commit a compare-and-swap. Without it, ARGUS would happily overwrite a
	// change someone else pushed between the read and the write — the same
	// optimistic-concurrency reasoning as the `resourceVersion` precondition on
	// cluster patches (lld/08 §5).
	PutFile(ctx context.Context, repo Repo, in PutFileInput) (commitSHA string, err error)

	// DeleteFile removes one path from a branch in a single commit.
	//
	// BACKLOG.md "still open" #2: the whole-file grammar could create and
	// replace a file's content but had no way to remove one — the correct fix
	// named by `AB1` ("delete one whole HPA manifest") and its `CRD-001`
	// addendum. Unlike PutFileInput.BaseSHA, which is empty exactly when
	// CREATING a file that does not exist yet, DeleteFileInput.BaseSHA is
	// always REQUIRED: there is no "delete a file that does not exist" case
	// to allow, so the same compare-and-swap precondition PutFile makes
	// optional for creation is mandatory here. A provider that cannot supply
	// one (see UpdatableFileReader) cannot be used to propose a deletion any
	// more than it can propose a write, for the identical reason.
	//
	// A required Provider method, not an optional capability the way
	// AtomicCommitter/CloneCredentialer are: both providers this package
	// implements (GitHub's Contents API, GitLab's Repository Files API)
	// expose an equivalent single-file delete with an equivalent
	// compare-and-swap precondition, so there is no asymmetry here for an
	// optional interface to paper over — see github.go/gitlab.go's DeleteFile
	// for the provider-specific detail.
	DeleteFile(ctx context.Context, repo Repo, in DeleteFileInput) (commitSHA string, err error)

	// OpenPullRequest opens a PR from head into base.
	OpenPullRequest(ctx context.Context, repo Repo, in PullRequestInput) (PullRequest, error)

	// PullRequestStatus reports whether a previously opened PR has merged.
	// Read-only counterpart to OpenPullRequest, for internal/orchestrator's
	// MergeSweeper — the AwaitingMerge -> Validating edge lld/08 specifies on
	// "a merge webhook" this build instead polls for.
	PullRequestStatus(ctx context.Context, repo Repo, number int) (PullRequestStatus, error)

	// IsAncestor reports whether ancestor's commit is contained in ref's
	// history (true when ref names the same commit as ancestor, too).
	//
	// BUGS.md 81: a GitOps controller's reported synced revision is not
	// always the literal merge commit — any later commit landing on the base
	// branch before the next sync makes the controller's revision a
	// descendant of the merge commit rather than equal to it, and the fix
	// this PR carried is present either way. internal/api.CheckPullRequestMerged
	// tries an exact-SHA comparison first (no network call, and true for the
	// overwhelmingly common case of nothing else landing in between) and
	// falls back to this only when that comparison is false — so a repository
	// where PRs merge slower than the sync interval never pays for it.
	IsAncestor(ctx context.Context, repo Repo, ancestor, ref string) (bool, error)
}

// UpdatableFileReader is the read half of the compare-and-swap, kept OFF
// Provider on purpose.
//
// Provider's doc comment says the SHA is deliberately opaque, and that is still
// right for the ordinary read: a caller locating a manifest has no business
// holding a token it might pass to the wrong write. But a caller that intends to
// commit needs the exact blob it read, so the capability is expressed as a
// separate interface a provider may satisfy rather than as a sixth method every
// provider must implement and every read-only caller can see.
//
// A provider that cannot supply a blob SHA therefore cannot be used to propose a
// change at all — which is the correct failure, not a limitation to work around:
// committing without one means overwriting whatever someone else pushed between
// the read and the write.
type UpdatableFileReader interface {
	ReadFileForUpdate(ctx context.Context, repo Repo, ref, path string) (content []byte, blobSHA string, err error)
}

// AtomicCommitter is implemented by a Provider that can commit several files
// as ONE atomic operation — one tree, one commit, one ref update — instead of
// the N sequential PutFile compare-and-swaps Provider itself provides.
//
// # Why this is optional, not a Provider method
//
// BACKLOG.md F24: `scm.Provider` is file-level on purpose (see PutFile's own
// doc comment) — that is exactly what makes a per-file blob compare-and-swap
// possible. But it also means a caller committing N files makes N sequential
// writes, and a conflict on file 3 of 5 leaves files 1-2 already landed on
// the fix branch with no pull request ever opened: safe (nothing merges) but
// littered (a human has to notice and delete the branch).
//
// GitHub's git-data API (blobs -> tree -> commit -> ref update) closes that
// gap: N files become one tree and one commit, and the ref update is the only
// step that touches the branch, so a conflict there leaves nothing landed at
// all. Not every provider's REST surface has an equivalent — GitLab's file
// API is one write per file with no multi-file tree endpoint (see gitlab.go's
// PutFile doc comment for the citations) — so this follows the same pattern
// as UpdatableFileReader and CloneCredentialer above: a capability a caller
// checks for by type assertion, never a method every Provider must
// implement. A provider that does not implement this is not degraded; a
// caller falls back to Provider.PutFile in a loop and keeps today's
// safe-but-littering behaviour, unchanged.
type AtomicCommitter interface {
	// PutFiles commits every entry in in.Files as ONE commit. Either all of
	// them land, atomically, or none do — including under a concurrent push
	// to the branch (or to any one of the paths being changed), which must be
	// caught as ErrConflict with NOTHING committed, never applied partially
	// and never silently overwritten.
	PutFiles(ctx context.Context, repo Repo, in PutFilesInput) (commitSHA string, err error)
}

// PutFilesInput is a multi-file, single-commit change — the atomic
// alternative to N sequential PutFileInput calls, used only through
// AtomicCommitter.
type PutFilesInput struct {
	// Branch is the fix branch every file is committed to.
	Branch string
	// BaseCommitSHA is the commit the branch currently points at — the
	// compare-and-swap token for the ref update half of this operation.
	// REQUIRED: without it the final ref update could not refuse a
	// concurrent push, which is the property this whole path exists for.
	BaseCommitSHA string
	// Files is every file to commit, in one atomic commit.
	Files []FileCommit
	// Message, Author and Trailers describe the ONE commit — unlike
	// PutFileInput, there is no per-file message, because there is no
	// per-file commit.
	Message  string
	Author   Identity
	Trailers []string
}

// FileCommit is one file within a PutFilesInput. It carries no branch,
// message, author or trailers of its own — those live on PutFilesInput,
// shared by the whole commit.
type FileCommit struct {
	Path    string
	Content []byte
	// BaseSHA is the blob SHA this file was read at (empty for a file being
	// created). An implementation MUST check this against the file's CURRENT
	// blob at that path before writing anything — the same compare-and-swap
	// guarantee PutFileInput.BaseSHA gives per file, reimplemented here
	// because the trees API has no per-entry precondition of its own.
	BaseSHA string
	// Delete marks this entry as a removal rather than a write: Content is
	// ignored and the path is removed from the resulting tree instead of
	// being written. BaseSHA is still REQUIRED and still checked — a delete
	// is a compare-and-swap against the file's current blob exactly like a
	// write is, so a path that moved under a concurrent commit is caught the
	// identical way. GitHub's git-data tree API represents this naturally: a
	// tree entry naming a path with a null sha removes that path from the
	// tree GitHub builds from base_tree, which is what makes a delete and a
	// write to DIFFERENT files land in the SAME atomic commit (BACKLOG.md
	// "still open" #2's mixed-batch case) — see github.go's PutFiles.
	Delete bool
}

// CloneCredentialer is implemented by a Provider that can supply the credential
// a git fetch needs, for the one operation that is not an API call.
//
// Deliberately a separate, optional interface rather than a field on Provider or
// on Binding, and the narrowness is the point. Every other thing ARGUS does to a
// repository goes through the provider's REST API, where the credential never
// leaves the provider value. Cloning does not: git needs it directly. So exactly
// one capability is exposed, on an interface a caller has to ask for by name, and
// a provider that cannot safely hand one over simply does not implement it — in
// which case file discovery is unavailable and the caller must be told the path
// instead, rather than the credential being obtained some other way.
type CloneCredentialer interface {
	// CloneToken returns the credential for an HTTPS git fetch. The caller must
	// not retain it beyond the operation it was requested for.
	CloneToken() string
}

// Repo identifies a repository on a provider.
type Repo struct {
	// Owner/Name for GitHub. For GitLab, Owner is the group path and Name the
	// project, joined with "/" to form the project path.
	Owner string
	Name  string
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

// PutFileInput is one file-level commit.
type PutFileInput struct {
	Branch  string
	Path    string
	Content []byte
	Message string
	// BaseSHA is the file's current blob SHA — the compare-and-swap token. Empty
	// only when creating a file that does not exist yet.
	BaseSHA string
	// Author and Trailers carry attribution. D-R9 moved attribution OFF the
	// credential: the commit is made by the machine user the token belongs to,
	// and the human who approved is named here. That is stronger provenance than
	// borrowing someone's token — a token proves whose credential was used, this
	// plus the audit chain proves who decided.
	Author   Identity
	Trailers []string
}

// DeleteFileInput is one file-level delete.
type DeleteFileInput struct {
	Branch  string
	Path    string
	Message string
	// BaseSHA is the file's current blob SHA — the compare-and-swap token.
	// ALWAYS required (unlike PutFileInput.BaseSHA, which is empty only for
	// a file being created): a delete has no analogous "the file does not
	// exist yet" case, so there is nothing an empty value could legitimately
	// mean here.
	BaseSHA  string
	Author   Identity
	Trailers []string
}

// Identity is a commit author.
type Identity struct {
	Name  string
	Email string
}

// messageWithTrailers appends git trailers to a commit message: a blank line,
// then one trailer per line at the end. This is where the approving human is
// named (D-R9), which is why trailers are a first-class field on every commit
// input rather than something a caller concatenates.
//
// One implementation for both providers and all three write paths (PutFile,
// PutFiles, DeleteFile) — the wire format is git's, not any one host's.
func messageWithTrailers(message string, trailers []string) string {
	if len(trailers) == 0 {
		return message
	}
	return strings.TrimRight(message, "\n") + "\n\n" + strings.Join(trailers, "\n")
}

// PullRequestInput is one PR.
type PullRequestInput struct {
	Title string
	Body  string
	Head  string // the branch with the change
	Base  string // where it is merging into
	// Labels let a caller mark how the change was verified — `lld/09` §100's
	// argus/verified-against-argo vs argus/verified-locally distinction.
	Labels []string
}

// PullRequest is what came back.
type PullRequest struct {
	Number int
	URL    string
	Head   string
	Base   string
}

// PullRequestStatus is one poll's answer to "has this PR merged".
type PullRequestStatus struct {
	// Merged is false for both "still open" and "closed without merging" —
	// State is what tells those two apart (BUGS.md 82: MergeSweeper now reads
	// it for exactly that reason, rather than treating a rejected PR the same
	// as one still under review).
	Merged bool
	// MergedAt is the zero time when Merged is false.
	MergedAt time.Time
	// CreatedAt is when the provider recorded the pull request as opened.
	// MergeSweeper uses it to flag one that has sat open, unmerged, past
	// DESIGN.md §12.3's staleness threshold ("if a PR sits unmerged past a
	// threshold, escalate") — BUGS.md 82's second half.
	CreatedAt time.Time
	// MergeCommitSHA is what landed on the base branch. Compared against the
	// GitOps controller's own reported synced revision to tell "merged" from
	// "merged AND converged" — a PR can merge while the controller has not
	// yet reconciled, or never does (this codebase's own name for that gap:
	// "repo-managed, but nothing applies the repo").
	MergeCommitSHA string
	// State is the provider's own word for it ("open"/"closed" on GitHub),
	// carried for logging — Merged already answers the one question that
	// drives behaviour.
	State string
}

var (
	// ErrNotFound is a missing repository, ref or path. A normal outcome while
	// searching for a manifest, so callers are expected to branch on it rather
	// than treat it as failure.
	ErrNotFound = errors.New("scm: not found")
	// ErrAlreadyExists is a branch (or PR) that is already there.
	ErrAlreadyExists = errors.New("scm: already exists")
	// ErrConflict is a compare-and-swap failure: the file moved under us.
	ErrConflict = errors.New("scm: the file changed since it was read")
	// ErrForbidden is an authorization failure — usually a token whose
	// repository selection or permissions are narrower than the operation.
	ErrForbidden = errors.New("scm: forbidden")
	// ErrCredentialExpired is called out separately from ErrForbidden because it
	// is the failure a fine-grained PAT will actually produce over time, and it
	// has a different fix (renew the token, not widen it). D-R9 flagged the
	// expiry as a requirement rather than a caveat for exactly this reason.
	ErrCredentialExpired = errors.New("scm: the stored credential has expired or been revoked")
)

// ParseRepoURL extracts a Repo from a clone URL.
//
// This is a security boundary, not a convenience. The URL arrives from a
// CLUSTER OBJECT — an Argo CD Application's `spec.source.repoURL` — which a
// tenant may be able to influence, and it reaches here via a model that also
// reads free-text incident descriptions. So it is treated as untrusted input,
// with the same rules `internal/gitops/clone.go` established:
//
//   - **https only.** `ssh://`, `git://` and especially `file://` are refused;
//     the last would turn "read the repo this object came from" into an
//     arbitrary local-file read on the hub.
//   - **No credentials in the URL.** Any userinfo is refused outright rather
//     than stripped, because a URL carrying one is a sign something upstream is
//     wrong and silently continuing hides it.
//   - **Host must match the binding.** Enforced by the caller, not here — see
//     MatchesHost.
func ParseRepoURL(raw string) (Repo, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Repo{}, "", errors.New("scm: repository URL is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return Repo{}, "", fmt.Errorf("scm: repository URL %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return Repo{}, "", fmt.Errorf("scm: repository URL scheme %q is refused — only https is allowed (a file:// or ssh:// URL arriving from a cluster object would be an arbitrary read)", u.Scheme)
	}
	if u.User != nil {
		return Repo{}, "", errors.New("scm: repository URL carries embedded credentials — refused rather than stripped, because a URL like this means something upstream is wrong")
	}
	if u.Host == "" {
		return Repo{}, "", fmt.Errorf("scm: repository URL %q has no host", raw)
	}

	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[len(parts)-1] == "" {
		return Repo{}, "", fmt.Errorf("scm: cannot read owner/name out of repository path %q", u.Path)
	}
	// Everything but the last segment is the owner, so a GitLab subgroup path
	// (group/subgroup/project) survives instead of being truncated.
	return Repo{Owner: strings.Join(parts[:len(parts)-1], "/"), Name: parts[len(parts)-1]}, u.Host, nil
}

// MatchesHost is exact, case-insensitive host comparison.
//
// No wildcards and no suffix matching, deliberately: `github.com` must not
// authorise `github.com.attacker.example`, which a naive `strings.HasSuffix`
// would wave straight through.
func MatchesHost(host, allowed string) bool {
	return strings.EqualFold(strings.TrimSpace(host), strings.TrimSpace(allowed))
}

// ParseRepoRef extracts a repository's IDENTITY from any URL form a GitOps
// controller might report, for matching only — never for transport.
//
// # Why this exists separately from ParseRepoURL
//
// ParseRepoURL answers "may ARGUS dial this?" and is deliberately https-only,
// because the URL arrives from a cluster object and a `file://` would turn a
// repository read into an arbitrary local read. That rule is right and unchanged.
//
// This function answers a different question: "is this the same repository the
// operator registered in Settings?" Nothing is dialled to answer it — ARGUS
// talks to the provider's REST API at the binding's own configured base URL,
// using the binding's own token, and the repository URL is never a transport.
// So the identity of a repository can safely be recognised in forms ARGUS would
// refuse to fetch.
//
// That distinction is not academic. Argo CD installations very commonly sync
// private repositories over SSH, so `spec.source.repoURL` reads
// `git@github.com:org/platform-config.git` while the operator registered
// `https://github.com/org/platform-config`. Those are the same repository. A
// matcher that could not see that would leave the entire pull-request path
// unreachable for a large share of real installations, and — worse — would say
// so by telling the operator to register a repository they had already
// registered.
//
// Refused, still: `file://`, any scheme that is not https/ssh, and any userinfo
// carrying a password. A bare `git@` username is accepted because it is the
// universal SSH convention and carries no secret; a password in a URL means
// something upstream is wrong and is refused rather than ignored.
func ParseRepoRef(raw string) (Repo, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Repo{}, "", errors.New("scm: repository URL is required")
	}

	// The scp-like form (`git@host:owner/name.git`) is not a URL at all —
	// url.Parse reads it as an opaque path — so it is recognised before parsing.
	// Distinguished from `ssh://` by having no "//" and exactly one ":" before
	// the path.
	if !strings.Contains(trimmed, "://") {
		// Split on the LAST "@": the userinfo cannot contain an unencoded one,
		// and taking the first would find a colon inside `user:password@...`
		// and read the password as a port.
		hostAndPath := trimmed
		if at := strings.LastIndex(trimmed, "@"); at >= 0 {
			if strings.Contains(trimmed[:at], ":") {
				return Repo{}, "", errors.New("scm: repository URL carries a password — refused rather than ignored, because a URL like this means something upstream is wrong")
			}
			hostAndPath = trimmed[at+1:]
		}
		if colon := strings.Index(hostAndPath, ":"); colon > 0 {
			repo, err := repoFromPath(hostAndPath[colon+1:], trimmed)
			if err != nil {
				return Repo{}, "", err
			}
			return repo, normalizeHost(hostAndPath[:colon]), nil
		}
		return Repo{}, "", fmt.Errorf("scm: cannot read a repository out of %q — expected https://host/owner/name, ssh://git@host/owner/name or git@host:owner/name", raw)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return Repo{}, "", fmt.Errorf("scm: repository URL %q is not a URL: %w", raw, err)
	}
	switch u.Scheme {
	case "https", "ssh":
	default:
		return Repo{}, "", fmt.Errorf("scm: repository URL scheme %q is refused — only https and ssh identify a remote repository (a file:// or git:// URL would not)", u.Scheme)
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return Repo{}, "", errors.New("scm: repository URL carries a password — refused rather than stripped, because a URL like this means something upstream is wrong")
		}
	}
	if u.Hostname() == "" {
		return Repo{}, "", fmt.Errorf("scm: repository URL %q has no host", raw)
	}
	repo, err := repoFromPath(u.Path, raw)
	if err != nil {
		return Repo{}, "", err
	}
	return repo, normalizeHost(u.Hostname()), nil
}

// repoFromPath splits owner/name out of a repository path, tolerating the
// `.git` suffix and surrounding slashes that differ purely by convention
// between one tool's output and another's.
func repoFromPath(path, raw string) (Repo, error) {
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[len(parts)-1] == "" {
		return Repo{}, fmt.Errorf("scm: cannot read owner/name out of repository path in %q", raw)
	}
	// Everything but the last segment is the owner, so a GitLab subgroup path
	// (group/subgroup/project) survives instead of being truncated.
	return Repo{Owner: strings.Join(parts[:len(parts)-1], "/"), Name: parts[len(parts)-1]}, nil
}

// normalizeHost lowercases and strips any port. DNS is case-insensitive, and a
// port differs between the same host's https and ssh endpoints — neither can be
// allowed to make one repository look like two.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// RepoKey is the stable identity of one repository: `host/owner/name`,
// lowercased.
//
// This is what a binding is looked up by, replacing an exact match on the URL
// string an operator happened to type. That match failed four of the five URL
// forms a real Argo CD installation produces — a missing `.git`, a trailing
// slash, a differently-cased host, an SSH remote — and each failure surfaced as
// "no binding for this repository, register it", pointing the operator at an
// action they had already taken.
//
// # The one deliberate loss, stated rather than hidden
//
// Owner and name are lowercased too, not just the host. GitHub treats them
// case-insensitively, so `Example-Org/repo` and `example-org/repo` genuinely are
// one repository and must match. GitLab paths are technically case-sensitive, so
// in theory this could collapse two distinct GitLab projects differing only in
// capitalisation within one namespace. That trade is deliberate: the case it
// fixes (an operator typing the org name with different capitalisation than the
// controller reports) is ordinary, and the case it risks requires two projects
// whose paths differ only by case — which GitLab itself discourages and which
// would also mean two bindings for near-identical URLs, an ambiguity the unique
// index now refuses outright.
func RepoKey(host string, repo Repo) string {
	return strings.ToLower(normalizeHost(host) + "/" + repo.Owner + "/" + repo.Name)
}
