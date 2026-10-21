package gitops

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"argus/internal/scm"
)

// Proposing a repository change as a pull request — one or several whole files
// — over provider APIs.
//
// # The shape of a repository change
//
// There is exactly one: a set of file edits, each carrying the file's whole
// proposed content. Not a field and a value; not a diff the model wrote. ARGUS
// reads the files at the pinned commit, takes the proposed content, computes
// the diff itself, and opens ONE pull request containing every edit.
//
// The single-field grammar that used to live here (ApplyFieldChange and its
// five structural assertions) was removed on 2026-08-28. It proved a strong
// property — exactly one scalar moved — about a change so narrow that most real
// fixes could not be expressed in it at all: one scalar, in one file, that
// already existed, in a file with no template markers. files.go's header has
// the full argument; the short version is that a verification mechanism must
// not be the ceiling on the capability it guards.
//
// # What actually stands between a model's proposal and a customer's cluster
//
// A human reads the diff and merges it. That is the gate, and it is a real one:
// nothing here merges anything, ever, and the pull request is opened by ARGUS's
// own machine account rather than by borrowing a person's credential.
//
// Around that sit the boundaries that are not judgement calls, all of them
// enforced in prepareChanges below, BEFORE any network write:
//
//  1. scm.ForbiddenPath — the privilege-escalation denylist. `.github/**`, CI
//     configuration, `scripts/**`, `Chart.yaml`, secrets and encrypted
//     content. ARGUS must never modify anything CI executes, nor content it
//     cannot read (DESIGN.md §11.1, §18.6).
//  2. Confinement to SourceDir — the directory this object's own GitOps
//     controller reports syncing. This is what stops an incident about
//     `envs/dev` opening a pull request against `envs/prod`.
//  3. Reads pinned to SyncedRevision — §11.4's "pin the SHA", the only
//     revision whose content is known to be what the cluster is running — and
//     a compare-and-swap on every push, so a file that moved underneath the
//     proposal is refused rather than overwritten.
//  4. No auto-merge. There is no code path in this package that merges.
//
// # Why the PR is labelled `argus/verified-locally`
//
// §11.4's verification table has two rows. With an Argo CD API connection
// registered, a proposal can additionally be diffed against what Argo itself
// would render (`argocd app manifests`), and earns `argus/verified-against-argo`.
// Without one — and no Argo integration exists in this build — the label must
// say `argus/verified-locally` and the pull-request body must state what was
// and was NOT checked, so a reviewer knows which claim is being made. That is a
// requirement of the table, not a nicety: a PR that looks verified but names no
// verification method is worse than an unverified one, because it borrows
// credibility it has not earned.

// LabelVerifiedLocally is §11.4's label for a change checked by ARGUS's own
// checks with no Argo CD cross-check. Every PR this package opens carries it.
const LabelVerifiedLocally = "argus/verified-locally"

// LabelAutomated marks the change as machine-proposed, so a repository's own
// rules (CODEOWNERS reviews, required approvals, merge queues) can key off it
// without parsing the title.
const LabelAutomated = "argus"

// maxProposedFiles bounds one proposal. A fix that genuinely spans more files
// than this is not a fix, it is a refactor, and it is not something a machine
// should be opening in one pull request against somebody's cluster source. A
// cost and blast-radius bound, not a security boundary — the denylist and the
// directory confinement are those.
const maxProposedFiles = 20

// Provenance is the attribution that goes on the commit and in the PR body —
// never on the credential.
//
// The PR is opened by the machine user whose token the binding holds, and the
// human who approved is recorded here. That is deliberately stronger provenance
// than borrowing a person's token: a token proves whose credential was used,
// this plus the §18.7 audit chain proves who decided.
type Provenance struct {
	// IncidentID is what ties the change back to everything ARGUS recorded
	// about why it is being proposed.
	IncidentID string
	// ApprovedBy identifies the human who authorised this — an email where one
	// is known, otherwise the user id. Named in a commit trailer and in the PR
	// body.
	ApprovedBy string
	// ClusterID and the object triple say WHERE the symptom was, which is the
	// first thing a reviewer of an unfamiliar PR needs.
	ClusterID string
	// ClusterName is that cluster's display name ("rke2 (personal test)").
	//
	// It exists because the pull request body is read on GitHub, by a human who
	// has no ARGUS session and cannot resolve anything: the body rendered
	// `| Cluster | cl_01m0kf0ckgkjk21yz6d77gd131 |`, which told a reviewer only
	// that SOME cluster was involved. The name leads and the id follows in the
	// same row — the id is kept because it is the join key for anyone who does
	// have ARGUS open, and because display names are editable and not unique
	// while the id is the durable identifier this change is actually attributed
	// to.
	//
	// Optional: when it is empty the row falls back to the id alone, which is
	// the behaviour this replaced. A reviewer seeing a bare id is worse than
	// seeing a name; a reviewer seeing a name ARGUS invented would be worse
	// than both.
	ClusterName string
	// RootCause is the analysis' own statement, quoted rather than paraphrased.
	// Optional.
	RootCause string
	// ResolvedFrom is how the repository target was determined, e.g.
	// "argoproj.io/Application argocd/my-app .status.sync.revision". Included
	// so the reviewer can check the claim that this repository and revision are
	// the right ones, rather than take it on trust.
	ResolvedFrom string
	// Author is the identity the commit is attributed to (the machine user).
	Author scm.Identity
}

// ProposalInput is one proposed pull request.
// RenderEvidence is BACKLOG.md F26's second promise, checked: not "these are
// the files, in full, as proposed" (this package's own machinery already
// proves that) but "this produces the intended change in the cluster" — what
// internal/render's render-and-diff answers by rendering the chart/overlay
// twice, once against the content at SyncedRevision and once with the
// proposed edits applied, and comparing the two.
//
// A nil *RenderEvidence anywhere in this package means exactly what an
// unadorned pull request already says today: rendering was not attempted —
// never a refusal, and never rendered as a claim of any kind. This package
// has no dependency on internal/render (which itself has no dependency on a
// Kubernetes client) precisely so a caller can compute this before ever
// calling ProposeChanges and pass it in as plain data — see
// internal/api/render_evidence.go for where that computation actually
// happens and why it degrades to nil rather than blocking the pull request.
type RenderEvidence struct {
	// Attempted is true whenever a render was actually run — separates
	// "we tried and could not tell" (Attempted true, Degraded non-empty)
	// from "we never tried" (nil *RenderEvidence, the caller's default).
	Attempted bool
	// RendererKind is "helm" or "kustomize".
	RendererKind string
	// Effective is true when the render found at least one object genuinely
	// differs between the original and proposed content — false is the
	// values-file-precedence finding this exists to catch: a real edit that
	// a later values file or chart default still overrides, changing
	// nothing a cluster would run.
	Effective bool
	// ObjectsCompared is how many rendered objects were compared.
	ObjectsCompared int
	// ObjectsChanged names each object the render found genuinely
	// different (kind/namespace/name), empty when Effective is false.
	ObjectsChanged []string
	// Summary is one sentence, already worded for a reviewer — quoted
	// verbatim into the pull request body and the audit/timeline record so
	// the claim is decided once and read identically everywhere.
	Summary string
	// Degraded is non-empty when a render was attempted but did not
	// produce a usable result (renderer error, timeout, sandbox
	// unreachable) — distinguishes an honest "attempted, inconclusive"
	// from a clean result.
	Degraded string
}

type ProposalInput struct {
	// Object is the live object this incident is about. It is provenance and
	// advisory context — the PR body names it, and ApplyFileEdit notes when a
	// file that used to declare it no longer does. It is NOT used to choose
	// which document to edit: a whole-file edit to a values.yaml has no
	// Kubernetes object in it to identify.
	Object ObjectRef
	// Files is the change: one or more paths, each with its whole proposed
	// content. At least one is required.
	Files []FileEdit
	// SyncedRevision is the commit the GitOps controller reports as applied
	// (`status.sync.revision`). REQUIRED and never a branch name.
	SyncedRevision string
	// SourceDir, when set, is the directory the controller reports syncing
	// (Argo's `spec.source.path`). Every proposed path must sit inside it.
	SourceDir string
	// BaseBranch is where the PR merges into. Empty asks the provider for the
	// repository's default branch, because a repository's default is not
	// always `main` and branching from the wrong base produces a PR full of
	// unrelated changes.
	BaseBranch string
	// Branch is the fix branch to create.
	Branch string
	// ForbiddenPaths is the binding's `spec.writeScope.forbiddenPaths`. Checked
	// here in addition to scm's own non-overridable list — see
	// scm/writescope.go.
	ForbiddenPaths []string
	// Provenance is the attribution.
	Provenance Provenance
	// RenderEvidence is F26's render-and-diff result, computed by the
	// caller BEFORE ProposeChanges runs — see that type's doc comment. Nil
	// (the zero value) means rendering was never attempted, which is the
	// same honest "unproven" this package already stated before F26 shipped
	// — passing it is a strict upgrade, never a new requirement.
	RenderEvidence *RenderEvidence
}

// Proposal is what was opened, plus everything needed to explain it afterwards.
type Proposal struct {
	PullRequest scm.PullRequest
	// Commits is one commit SHA per file committed, in the order committed —
	// or a single entry when the provider committed every file atomically as
	// one commit (BACKLOG.md F24: only when the provider implements
	// scm.AtomicCommitter and more than one file changed). CommitSHA is the
	// last of them (the branch head) either way. BranchPoint is what the fix
	// branch was cut from.
	Commits     []string
	CommitSHA   string
	BranchPoint string
	// Verification is the per-file record quoted in the PR body.
	Verification ChangeVerification
	// RenderEvidence carries through ProposalInput.RenderEvidence unchanged
	// — recorded here too so a caller building an audit/timeline record has
	// it without holding on to its own copy of the input.
	RenderEvidence *RenderEvidence
	// LabelWarning is non-empty when the PR was opened but could not be
	// labelled. Surfaced rather than swallowed: the label is how §11.4's table
	// communicates which verification was performed, so a PR missing it is a
	// PR making a weaker claim than the reviewer will assume.
	LabelWarning string
}

// Preview is what a proposal WOULD do: the checked edits and their diffs, with
// nothing branched, committed or opened.
type Preview struct {
	// SyncedRevision is the commit the files were read at — the one the GitOps
	// controller reports applied, not the branch head.
	SyncedRevision string
	Verification   ChangeVerification
	// RenderEvidence carries ProposalInput.RenderEvidence through unchanged —
	// BACKLOG.md F28 finding 2: render evidence used to reach only the two
	// paths that OPEN a pull request (Proposal.RenderEvidence above), never
	// the preview a human reviews BEFORE approving one. Nil means exactly
	// what it means everywhere else this type appears: rendering was never
	// attempted, not a refusal and not a claim.
	RenderEvidence *RenderEvidence
}

// PreviewChanges runs the whole read-and-check pipeline and stops.
//
// Same code as ProposeChanges up to the point where it would cut a branch, and
// that sameness is the only thing that makes a preview worth showing: a preview
// computed by a second, parallel path would be a claim about what a commit
// would do, and this is the actual computation the commit uses. It also means
// every refusal an operator can hit — a forbidden path, a file outside the
// synced directory, unparseable YAML, drift since the synced commit — surfaces
// in the preview rather than after they press the button.
func PreviewChanges(ctx context.Context, p scm.Provider, repo scm.Repo, in ProposalInput) (Preview, error) {
	changes, err := prepareChanges(ctx, p, repo, in)
	if err != nil {
		return Preview{}, err
	}
	return Preview{SyncedRevision: in.SyncedRevision, Verification: summarize(changes), RenderEvidence: in.RenderEvidence}, nil
}

// ProposeChanges runs the whole path: read each file at the synced commit,
// check and diff the proposed content, branch, commit each changed file, open
// one pull request.
//
// It returns an error and opens nothing if any check fails. There is no partial
// success before the first commit: everything up to CreateBranch is a read.
func ProposeChanges(ctx context.Context, p scm.Provider, repo scm.Repo, in ProposalInput) (Proposal, error) {
	// A fix branch is required here and NOT in prepareChanges: a preview cuts
	// no branch, so demanding a name for one would refuse a read that is
	// entirely valid.
	if in.Branch == "" {
		return Proposal{}, errors.New("gitops: a fix branch name is required")
	}

	// The read phase, shared verbatim with PreviewChanges. Every refusal below
	// this line is one an operator has already seen in a preview, if they took
	// one.
	changes, err := prepareChanges(ctx, p, repo, in)
	if err != nil {
		return Proposal{}, err
	}
	verification := summarize(changes)

	base := in.BaseBranch
	if base == "" {
		base, err = p.DefaultBranch(ctx, repo)
		if err != nil {
			return Proposal{}, fmt.Errorf("gitops: could not determine the base branch: %w", err)
		}
	}

	// The branch is cut from the BASE BRANCH's head, not from the synced
	// commit, while the edits were computed against the synced commit. That
	// combination is deliberate and does real work:
	//
	//   - Branching from the synced commit would make the PR's diff against
	//     base include everything that landed on base since — shown as
	//     reverts. A PR full of unrelated reversions is a PR nobody can review.
	//   - Reading at the synced commit is what §11.4 requires: it is the only
	//     revision whose content is known to be what the cluster is running.
	//   - The blob SHA read at the synced commit is then used as each commit's
	//     compare-and-swap token against the branch. If a file is unchanged
	//     between the synced commit and base's head, the blob SHA is the same
	//     object and the commit lands cleanly. If the file DID move in between,
	//     the provider refuses with ErrConflict — the correct outcome, because
	//     the edit was computed against content that is no longer there.
	branchPoint, err := p.ResolveRef(ctx, repo, base)
	if err != nil {
		return Proposal{}, fmt.Errorf("gitops: could not resolve the base branch %q: %w", base, err)
	}
	if err := p.CreateBranch(ctx, repo, in.Branch, branchPoint); err != nil {
		if errors.Is(err, scm.ErrAlreadyExists) {
			return Proposal{}, fmt.Errorf("gitops: branch %q already exists in %s. It is named after this incident, so it is very likely an earlier proposal for the same problem — review or delete that branch rather than adding a second, conflicting commit to it", in.Branch, repo)
		}
		return Proposal{}, err
	}

	// One commit per file, in submission order — UNLESS the provider can
	// commit them all as one atomic operation and there is more than one file
	// to commit, in which case that path is used instead (BACKLOG.md F24). A
	// single file gains nothing from going through the trees API — a lone
	// PutFile is already one compare-and-swap — so it always takes the
	// simpler path below, even against a provider that supports the atomic
	// one.
	//
	// # The sequential path's real, live consequence — and why it still exists
	//
	// Not one atomic tree commit, and the trade is worth stating: the provider
	// surface this package is built on is file-level (scm.PutFile), which is
	// what makes the blob-SHA compare-and-swap available per file. Committing N
	// files means N sequential compare-and-swaps rather than one, so a
	// concurrent push that moves the third file is caught on the third commit,
	// after the first two have landed on the FIX BRANCH. Nothing has merged and
	// nothing is in base at that point — the branch exists with a partial
	// change and no pull request, and the error below says exactly that so a
	// human can delete it. That is a recoverable, visible state; silently
	// merging a partial change is what would not be, and cannot happen here.
	//
	// This is still the ONLY path available for a provider that does not
	// implement scm.AtomicCommitter (GitLab, today — its file API has no
	// multi-file tree equivalent; see gitlab.go's PutFile doc comment), and it
	// is unchanged from before F24: same compare-and-swap, same partial-branch
	// error, same recovery-by-deleting-the-branch story.
	var commits []string
	changed := verification.Changed()
	// One set of trailers for every commit this proposal makes: trailers()
	// is a pure function of the proposal's provenance, verification summary
	// and render evidence, none of which vary per file.
	commitTrailers := trailers(in.Provenance, verification, in.RenderEvidence)
	if committer, ok := p.(scm.AtomicCommitter); ok && len(changed) > 1 {
		files := make([]scm.FileCommit, 0, len(changed))
		for _, f := range changed {
			files = append(files, scm.FileCommit{Path: f.Path, Content: f.Content, BaseSHA: f.BlobSHA, Delete: f.Deleted})
		}
		sha, perr := committer.PutFiles(ctx, repo, scm.PutFilesInput{
			Branch:        in.Branch,
			BaseCommitSHA: branchPoint,
			Files:         files,
			Message:       atomicCommitMessage(in, changed),
			Author:        in.Provenance.Author,
			Trailers:      commitTrailers,
		})
		if perr != nil {
			if errors.Is(perr, scm.ErrConflict) {
				return Proposal{}, fmt.Errorf("gitops: branch %q moved since these files were read, so the atomic commit could not be applied. Nothing was committed — delete branch %q and re-run this once the incident has been re-analysed against the current files: %w",
					in.Branch, in.Branch, perr)
			}
			return Proposal{}, fmt.Errorf("gitops: %d file(s) could not be committed atomically to branch %q. Nothing was committed — delete that branch: %w",
				len(changed), in.Branch, perr)
		}
		commits = []string{sha}
	} else {
		for _, f := range changed {
			var sha string
			var perr error
			if f.Deleted {
				sha, perr = p.DeleteFile(ctx, repo, scm.DeleteFileInput{
					Branch:   in.Branch,
					Path:     f.Path,
					Message:  commitMessage(in, f),
					BaseSHA:  f.BlobSHA,
					Author:   in.Provenance.Author,
					Trailers: commitTrailers,
				})
			} else {
				sha, perr = p.PutFile(ctx, repo, scm.PutFileInput{
					Branch:   in.Branch,
					Path:     f.Path,
					Content:  f.Content,
					Message:  commitMessage(in, f),
					BaseSHA:  f.BlobSHA,
					Author:   in.Provenance.Author,
					Trailers: commitTrailers,
				})
			}
			if perr != nil {
				if errors.Is(perr, scm.ErrConflict) {
					return Proposal{}, fmt.Errorf("gitops: %s changed between the synced commit %s and %s, so the edit computed for it no longer applies. %s; re-run this once the incident has been re-analysed against the current files: %w",
						f.Path, shortSHA(in.SyncedRevision), base, partialCommitNote(in.Branch, commits, len(changed)), perr)
				}
				return Proposal{}, fmt.Errorf("gitops: %s could not be committed to branch %q. %s: %w",
					f.Path, in.Branch, partialCommitNote(in.Branch, commits, len(changed)), perr)
			}
			commits = append(commits, sha)
		}
	}

	pr, err := p.OpenPullRequest(ctx, repo, scm.PullRequestInput{
		Title:  pullRequestTitle(in, verification),
		Body:   pullRequestBody(in, verification, base, branchPoint, p.Name()),
		Head:   in.Branch,
		Base:   base,
		Labels: []string{LabelAutomated, LabelVerifiedLocally},
	})
	out := Proposal{
		Commits:        commits,
		CommitSHA:      lastOf(commits),
		BranchPoint:    branchPoint,
		Verification:   verification,
		RenderEvidence: in.RenderEvidence,
	}
	if err != nil {
		// OpenPullRequest returns the PR alongside a labelling failure (see its
		// doc comment), so a non-nil error with a real PR number is "opened but
		// not labelled" and must not be reported as "nothing happened".
		if pr.Number != 0 {
			out.PullRequest = pr
			out.LabelWarning = err.Error()
			return out, nil
		}
		return Proposal{}, fmt.Errorf("gitops: the change was committed to branch %q (%d commit(s), head %s) but the pull request could not be opened — open it by hand from that branch: %w",
			in.Branch, len(commits), shortSHA(lastOf(commits)), err)
	}
	out.PullRequest = pr
	return out, nil
}

// prepareChanges is the READ phase — validation, the path refusals, reading
// each file at the synced commit, and computing the checked, diffed edit. It
// performs no write of any kind.
//
// Extracted from ProposeChanges so that PreviewChanges and ProposeChanges run
// the SAME code. Every path refusal is made here, before the first byte of any
// file is read, so a path that must never be written is refused whether or not
// it exists.
func prepareChanges(ctx context.Context, p scm.Provider, repo scm.Repo, in ProposalInput) ([]FileChange, error) {
	// A provider that cannot hand back the blob SHA it read cannot make the
	// commit a compare-and-swap, and committing without one means overwriting
	// whatever someone pushed between the read and the write. Refused rather
	// than degraded.
	reader, ok := p.(scm.UpdatableFileReader)
	if !ok {
		return nil, fmt.Errorf("gitops: provider %q cannot read a file with its blob SHA, so a commit against it could not be a compare-and-swap", p.Name())
	}
	if in.SyncedRevision == "" {
		// §11.4: "Pin the SHA. Use status.sync.revision, not HEAD. If someone
		// pushed in the meantime, rendering HEAD produces a manifest that
		// doesn't match the live object, and every subsequent inference is
		// wrong." With no pinned revision there is no commit whose content is
		// known to be what is running, so there is nothing to compute against.
		return nil, errors.New("gitops: no synced commit is recorded for this object, so there is no revision whose content is known to be what is running — refusing to propose a change against a moving branch")
	}
	if len(in.Files) == 0 {
		return nil, errors.New("gitops: a repository change is one or more files with their proposed content, and none were given")
	}
	if len(in.Files) > maxProposedFiles {
		return nil, fmt.Errorf("gitops: this proposal names %d files, over the %d-file bound for one pull request", len(in.Files), maxProposedFiles)
	}

	// Security checks first, and before any network call, for EVERY file.
	seen := make(map[string]bool, len(in.Files))
	normalized := make([]FileEdit, 0, len(in.Files))
	for _, f := range in.Files {
		clean := normalizeRepoPath(f.Path)
		if clean == "" {
			return nil, errors.New("gitops: every proposed file must name a path")
		}
		if seen[clean] {
			// Two edits to one path in one proposal is a caller disagreeing
			// with itself about what the file should contain. Reconciling that
			// silently — last one wins — is how a pull request ends up holding
			// content nobody chose.
			return nil, fmt.Errorf("gitops: %s appears twice in this proposal; a file may be given one proposed content, not two", clean)
		}
		seen[clean] = true
		if pattern := scm.ForbiddenPath(clean, in.ForbiddenPaths); pattern != "" {
			return nil, fmt.Errorf("gitops: refusing to write %s — it matches the forbidden path %q. ARGUS must never be able to modify anything CI executes, or content it cannot read", clean, pattern)
		}
		if in.SourceDir != "" && !scm.WithinRepoDir(in.SourceDir, clean) {
			// The directory comes from the controller's own reported path; the
			// file comes from the request (or from the model). Confining one to
			// the other is what stops an incident about `envs/dev` being used
			// to open a pull request against `envs/prod`.
			return nil, fmt.Errorf("gitops: %s is outside %s, the path this object's GitOps controller reports syncing — refusing to change a file the controller that owns this object does not read", clean, in.SourceDir)
		}
		normalized = append(normalized, FileEdit{Path: clean, Content: f.Content, Delete: f.Delete})
	}

	changes := make([]FileChange, 0, len(normalized))
	anyChanged := false
	for _, f := range normalized {
		content, blobSHA, err := reader.ReadFileForUpdate(ctx, repo, in.SyncedRevision, f.Path)
		created := false
		switch {
		case err == nil:
			if blobSHA == "" {
				return nil, fmt.Errorf("gitops: %s came back without a blob SHA, so the commit could not be a compare-and-swap", f.Path)
			}
		case errors.Is(err, scm.ErrNotFound):
			if f.Delete {
				// There is no "create" case to mirror for a delete — a path
				// that does not exist at the synced commit cannot be removed,
				// and a proposal that thinks it can is a proposal built on a
				// wrong belief about the repository's current state, not a
				// content problem a corrected byte string could fix. Wrapped
				// as scm.ErrNotFound (not ErrVerificationFailed) deliberately:
				// writeRepositoryChangeFailure already maps it to a clear 422,
				// and openpr_correction.go's openPRRefusalCorrectionEligible
				// deliberately does NOT treat scm.ErrNotFound as
				// content-fixable, for the identical reason it excludes a
				// git-level conflict — retrying with different bytes cannot
				// un-delete a file that was never there.
				return nil, fmt.Errorf("gitops: refusing to delete %s — it does not exist at the synced commit %s, so there is nothing to remove: %w", f.Path, in.SyncedRevision, scm.ErrNotFound)
			}
			// A file that does not exist at the synced commit is created by
			// this change. Allowed: adding a manifest, adding an overlay patch
			// and adding a values file are all legitimate fixes, and the path
			// has already passed the denylist and the directory confinement,
			// which is what actually bounds where ARGUS may write.
			created, content, blobSHA = true, nil, ""
		default:
			return nil, err
		}

		var change FileChange
		if f.Delete {
			change, err = ApplyFileDelete(content, f.Path, in.Object)
		} else {
			change, err = ApplyFileEdit(content, f, created, in.Object)
		}
		if err != nil {
			return nil, err
		}
		change.BlobSHA = blobSHA
		if !change.Unchanged {
			anyChanged = true
		}
		changes = append(changes, change)
	}
	if !anyChanged {
		return nil, ErrNothingToChange
	}
	return changes, nil
}

// normalizeRepoPath trims and slash-normalises a repository-relative path, and
// refuses anything that is not one. Traversal and absolute paths are rejected
// here rather than left for scm.WithinRepoDir, because a proposal with no
// SourceDir would otherwise have nothing checking them at all.
func normalizeRepoPath(p string) string {
	clean := strings.Trim(strings.TrimSpace(strings.ReplaceAll(p, "\\", "/")), "/")
	if clean == "" || clean == "." {
		return ""
	}
	if path.Clean(clean) != clean {
		// "a/../b", "./a", "a//b" — all normalise to something else, and a
		// path that does not survive Clean unchanged is not a path this
		// package will write to.
		return ""
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return ""
		}
	}
	return clean
}

func partialCommitNote(branch string, commits []string, total int) string {
	if len(commits) == 0 {
		return fmt.Sprintf("Nothing was committed (branch %q was created and can be deleted)", branch)
	}
	return fmt.Sprintf("%d of %d file(s) were already committed to branch %q and NO pull request was opened — delete that branch, nothing has merged", len(commits), total, branch)
}

func lastOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

// maxTitleLen bounds the pull request TITLE, which is not a commit subject —
// commitMessage writes those separately, and only that one is bound by the
// 72-character git convention. A provider allows far more here (GitHub's cap is
// 256), and the real constraint is that the title stays readable in a list
// without wrapping to a third line.
//
// 100 rather than 72 for a measured reason: the scope is an object, and a
// realistic namespace/name ("argus-gitops-rke2/api") spends 21 of the budget
// before the summary starts. At 72 the summary was cut mid-phrase on the very
// first live example this was checked against, producing a title as uninformative
// as the file path it replaced.
const maxTitleLen = 100

func pullRequestTitle(in ProposalInput, v ChangeVerification) string {
	// §11.1's default titleTemplate shape, "fix({cluster}/{namespace}):
	// {summary}", with the object rather than the cluster id in the scope: a
	// reviewer in the repository knows their namespaces and has never seen an
	// ARGUS cluster id. (There is no configured titleTemplate anywhere in this
	// codebase — §11.1 describes the DEFAULT shape and nothing reads an
	// override — so this is the only title any pull request gets.)
	//
	// What changed here is the {summary} half. It rendered "update
	// apps/api/deployment.yaml": a path, which the Files row of the body
	// already states, and which tells someone scanning a list of pull requests
	// nothing about whether this one is worth opening. The point of the change
	// is WHY, and the analysis has already written that sentence — so the title
	// quotes the root cause rather than paraphrasing it or inventing a
	// description of the diff, which would be a claim nothing verified.
	//
	// The file-based shapes remain as the fallback, not as dead code: a pull
	// request opened through the self-service repository-change route can have
	// no analysis behind it, and RootCause is documented Optional. Naming the
	// file is a weak title but a true one; a title asserting a cause that was
	// never determined would not be.
	where := objectScope(in.Object)
	if summary := titleSummary(in.Provenance.RootCause, maxTitleLen-len(where)-len("fix(): ")); summary != "" {
		return fmt.Sprintf("fix(%s): %s", where, summary)
	}
	paths := v.Paths()
	switch len(paths) {
	case 0:
		return fmt.Sprintf("fix(%s): repository change", where)
	case 1:
		return fmt.Sprintf("fix(%s): update %s", where, paths[0])
	default:
		return fmt.Sprintf("fix(%s): update %d files under %s", where, len(paths), commonDir(paths))
	}
}

// titleSummary reduces a root-cause statement to one title-sized clause.
//
// The root cause is free prose written for the incident page — it can run to
// paragraphs, carry markdown, and contain newlines, none of which survive a git
// subject line. This takes the first sentence, flattens it, and truncates at a
// word boundary with an ellipsis so a cut is visibly a cut rather than a
// sentence that appears to end early.
//
// Returns "" when there is nothing usable, which is how the caller knows to fall
// back. A budget too small to fit anything meaningful also returns "" rather
// than emitting a two-word stub: "fix(some-very-long-namespace/name): The…" is
// worse than naming the file.
func titleSummary(rootCause string, budget int) string {
	const minUsefulTitle = 24
	if budget < minUsefulTitle {
		return ""
	}
	// Flatten: markdown emphasis/code markers and any run of whitespace
	// (including the newlines that make this multi-line prose) collapse to
	// single spaces.
	flat := strings.Join(strings.Fields(strings.NewReplacer("`", "", "*", "", "_", "", "#", "").Replace(rootCause)), " ")
	if flat == "" {
		return ""
	}
	// First sentence. A period followed by a space is the only boundary trusted
	// here — splitting on "." alone would cut "128Mi. " correctly but also
	// "v1.24.3" and "apps/v1.Deployment" wrongly.
	if i := strings.Index(flat, ". "); i > 0 {
		flat = flat[:i]
	}
	flat = strings.TrimRight(flat, ".")
	if len(flat) <= budget {
		return flat
	}
	// Truncate on a word boundary, leaving room for the ellipsis.
	cut := flat[:budget-1]
	if i := strings.LastIndex(cut, " "); i >= minUsefulTitle {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,;:-") + "\u2026"
}

// commonDir is the deepest directory every path shares, for a multi-file
// title. Falls back to the repository root marker when they share nothing.
func commonDir(paths []string) string {
	if len(paths) == 0 {
		return "/"
	}
	parts := strings.Split(path.Dir(paths[0]), "/")
	for _, p := range paths[1:] {
		other := strings.Split(path.Dir(p), "/")
		n := 0
		for n < len(parts) && n < len(other) && parts[n] == other[n] {
			n++
		}
		parts = parts[:n]
	}
	joined := strings.Join(parts, "/")
	if joined == "" || joined == "." {
		return "/"
	}
	return joined
}

// atomicCommitMessage is the ONE commit message for a multi-file atomic
// commit — commitMessage's per-file shape does not apply because there is no
// per-file commit to attach it to.
func atomicCommitMessage(in ProposalInput, changed []FileChange) string {
	var b strings.Builder
	where := objectScope(in.Object)
	fmt.Fprintf(&b, "fix(%s): update %d file(s)\n\n", where, len(changed))
	added, removed := 0, 0
	for _, f := range changed {
		verb := "update"
		switch {
		case f.Created:
			verb = "add"
		case f.Deleted:
			verb = "delete"
		}
		fmt.Fprintf(&b, "- %s %s\n", verb, f.Path)
		added += f.LinesAdded
		removed += f.LinesRemoved
	}
	fmt.Fprintf(&b, "\n%d line(s) added, %d line(s) removed, across %d file(s).\n", added, removed, len(changed))
	if in.Provenance.RootCause != "" {
		fmt.Fprintf(&b, "\n%s\n", in.Provenance.RootCause)
	}
	return b.String()
}

func commitMessage(in ProposalInput, f FileChange) string {
	var b strings.Builder
	verb := "update"
	switch {
	case f.Created:
		verb = "add"
	case f.Deleted:
		verb = "delete"
	}
	where := objectScope(in.Object)
	fmt.Fprintf(&b, "fix(%s): %s %s\n\n", where, verb, f.Path)
	fmt.Fprintf(&b, "%d line(s) added, %d line(s) removed.\n", f.LinesAdded, f.LinesRemoved)
	if in.Provenance.RootCause != "" {
		fmt.Fprintf(&b, "\n%s\n", in.Provenance.RootCause)
	}
	return b.String()
}

// trailers carry the attribution and the verification claim in machine-readable
// form. Attribution is here on purpose: the commit is authored by the machine
// user the token belongs to, and the human who approved is named in the
// trailer, so `git log` answers "who decided this" without anyone having to
// borrow a colleague's credential to make it look right.
func trailers(prov Provenance, v ChangeVerification, re *RenderEvidence) []string {
	out := []string{}
	if prov.ApprovedBy != "" {
		out = append(out, "Approved-by: "+prov.ApprovedBy)
	}
	if prov.IncidentID != "" {
		out = append(out, "Argus-Incident: "+prov.IncidentID)
	}
	if prov.ClusterID != "" {
		out = append(out, "Argus-Cluster: "+prov.ClusterID)
	}
	// Named so it is greppable in a repository's history: every ARGUS commit
	// says which verification it passed, and this one says the local checks
	// only.
	out = append(out, "Argus-Verified: "+LabelVerifiedLocally)
	out = append(out, fmt.Sprintf("Argus-Edit: %d file(s), +%d/-%d lines", v.FilesChanged, v.LinesAdded, v.LinesRemoved))
	if len(v.Advisories) > 0 {
		// Greppable, and the machine-readable half of the body's own statement:
		// this change carries things ARGUS could not check and a reviewer must.
		out = append(out, fmt.Sprintf("Argus-Advisories: %d", len(v.Advisories)))
	}
	// BACKLOG.md F26: the render-and-diff result, greppable the same way the
	// verification line above is — absent entirely when rendering was never
	// attempted, never a line claiming a check that didn't run.
	if re != nil && re.Attempted {
		if re.Degraded != "" {
			out = append(out, "Argus-Render: degraded ("+re.Degraded+")")
		} else if re.Effective {
			out = append(out, fmt.Sprintf("Argus-Render: effective (%s, %d/%d object(s) changed)", re.RendererKind, len(re.ObjectsChanged), re.ObjectsCompared))
		} else {
			out = append(out, fmt.Sprintf("Argus-Render: no-effective-change (%s, %d object(s) compared)", re.RendererKind, re.ObjectsCompared))
		}
	}
	return out
}

// renderedDeltaSection is lld/09-repo-gitops-design.md §7's "## Rendered
// delta" template slot — BACKLOG.md F26's promotion of "this produces the
// intended change in the cluster" from stated-as-unproven to actually
// checked, where a renderer is available at all. Every branch below states
// plainly what class of claim is being made, because the entry this exists
// for is explicit that a badge for a check that didn't run is worse than no
// badge.
func renderedDeltaSection(re *RenderEvidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Rendered delta\n\n")
	switch {
	case re == nil || !re.Attempted:
		fmt.Fprintf(&b, "**Not attempted.** ARGUS did not render this chart/overlay and compare the result against what the repository's content renders to today. This is the same limitation the whole-file grammar has always disclosed: the diffs above show what changed in the SOURCE, not what changes in the CLUSTER — for a plain-YAML change the two are the same thing, but for a Helm values file or a Kustomize overlay they are not, and nothing here confirms which case this is.\n\n")
	case re.Degraded != "":
		fmt.Fprintf(&b, "**Attempted, inconclusive.** ARGUS tried to render both the original and proposed content and compare them, and could not produce a usable result (%s). Treat this exactly as if rendering had not been attempted — review the diffs above as the only evidence.\n\n", re.Degraded)
	case !re.Effective:
		fmt.Fprintf(&b, "**No effective change.** ARGUS rendered this %s chart/overlay twice — once against the repository content at the commit above, once with this pull request's edits applied — and compared %d rendered object(s). They are IDENTICAL. This is very likely the values-file-precedence trap this check exists to catch: the edited file is real and related, but a chart default or a later values file still wins, so merging this pull request would change no object in the cluster. **Verify this is intentional before merging** — if the goal was to change cluster behaviour, this diff will not do it.\n\n", re.RendererKind, re.ObjectsCompared)
	default:
		fmt.Fprintf(&b, "**Effective change confirmed.** ARGUS rendered this %s chart/overlay twice — once against the repository content at the commit above, once with this pull request's edits applied — and compared %d rendered object(s). %d differ:\n\n", re.RendererKind, re.ObjectsCompared, len(re.ObjectsChanged))
		for _, o := range re.ObjectsChanged {
			fmt.Fprintf(&b, "- `%s`\n", o)
		}
		fmt.Fprintf(&b, "\n")
	}
	if re != nil && re.Attempted && re.Summary != "" {
		fmt.Fprintf(&b, "_%s_\n\n", re.Summary)
	}
	return b.String()
}

// pullRequestBody is what a reviewer actually reads, and it is written to be
// checkable rather than persuasive.
//
// The structure is fixed by what §11.4 requires a PR to disclose: the change
// itself, the diff, the checks that were performed, **the checks that were NOT
// performed** (the `argus/verified-locally` row of its table, plus every
// per-file advisory), and the provenance chain back to the incident and the
// human who approved it.
func pullRequestBody(in ProposalInput, v ChangeVerification, base, branchPoint, providerName string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "ARGUS is proposing this change because the object it fixes is managed from this repository, so an in-place change to the cluster would be reverted by the next reconcile.\n\n")

	changed := v.Changed()
	fmt.Fprintf(&b, "## The change\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Files | %s |\n", strings.Join(backticked(v.Paths()), ", "))
	fmt.Fprintf(&b, "| Edit | %d file(s), %d line(s) added, %d line(s) removed |\n", v.FilesChanged, v.LinesAdded, v.LinesRemoved)
	fmt.Fprintf(&b, "| Object | `%s` `%s` in namespace `%s` |\n", orDash(in.Object.Kind), orDash(in.Object.Name), orDash(in.Object.Namespace))
	if name := in.Provenance.ClusterName; name != "" {
		// Name first, id second and parenthesised — see Provenance.ClusterName.
		// The name is NOT backticked: it is prose a human reads, and code-span
		// styling on "rke2 (personal test)" implies it is something to copy.
		fmt.Fprintf(&b, "| Cluster | %s (`%s`) |\n", name, in.Provenance.ClusterID)
	} else if in.Provenance.ClusterID != "" {
		fmt.Fprintf(&b, "| Cluster | `%s` |\n", in.Provenance.ClusterID)
	}
	fmt.Fprintf(&b, "| Read at | `%s` — the commit this object's GitOps controller reports as synced, not the branch head |\n", in.SyncedRevision)
	fmt.Fprintf(&b, "| Branched from | `%s` (`%s`) |\n\n", shortSHA(branchPoint), base)

	for _, f := range changed {
		heading := f.Path
		switch {
		case f.Created:
			heading += " (new file)"
		case f.Deleted:
			heading += " (DELETED)"
		}
		fmt.Fprintf(&b, "### `%s`\n\n```diff\n--- a/%s\n+++ b/%s\n%s```\n\n", heading, f.Path, f.Path, f.Diff)
	}

	if in.Provenance.RootCause != "" {
		fmt.Fprintf(&b, "## Why\n\n%s\n\n", in.Provenance.RootCause)
	}

	fmt.Fprintf(&b, "## What ARGUS checked\n\n")
	fmt.Fprintf(&b, "This is a whole-file change: ARGUS was given the content each file should end up holding, read each file at the commit above, and computed the diffs shown here itself. It does not claim the change is correct — the diff is the claim, and reviewing it is the check that matters. What ARGUS did establish before opening this:\n\n")
	fmt.Fprintf(&b, "- every path is inside `%s`, the directory this object's GitOps controller reports syncing\n", orDash(in.SourceDir))
	fmt.Fprintf(&b, "- no path matches ARGUS's forbidden-path denylist (CI configuration, scripts, chart metadata, secrets and encrypted content are never writable)\n")
	fmt.Fprintf(&b, "- every file was read at the pinned synced commit, and each commit here is a compare-and-swap against the blob that was read — if a file had moved since, this pull request would not exist\n")
	for _, c := range v.Checks {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	fmt.Fprintf(&b, "\nHad any of those failed, no branch and no pull request would have been created.\n\n")

	fmt.Fprintf(&b, "%s", renderedDeltaSection(in.RenderEvidence))

	fmt.Fprintf(&b, "## What was NOT checked\n\n")
	fmt.Fprintf(&b, "**ARGUS makes no claim that only the intended thing changed.** Review the diffs above as carefully as you would review a hand-written patch, not as a change ARGUS has already confirmed is correct.\n\n")
	if len(v.Advisories) > 0 {
		fmt.Fprintf(&b, "Specific things a reviewer has to check because ARGUS could not:\n\n")
		for _, a := range v.Advisories {
			fmt.Fprintf(&b, "- %s\n", a)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "This change is labelled `%s`, not `argus/verified-against-argo`. **The result was not cross-checked against what Argo CD itself would render**, because no Argo CD API connection is registered with ARGUS. Argo-side Helm values, parameter overrides or a config-management plugin could therefore produce a different result from the one shown above.\n\n", LabelVerifiedLocally)

	fmt.Fprintf(&b, "## Provenance\n\n")
	if in.Provenance.IncidentID != "" {
		fmt.Fprintf(&b, "- Incident: `%s`\n", in.Provenance.IncidentID)
	}
	if in.Provenance.ApprovedBy != "" {
		fmt.Fprintf(&b, "- Approved by: %s — this pull request was opened by ARGUS's own machine account on their behalf, not with their credential.\n", in.Provenance.ApprovedBy)
	}
	if in.Provenance.ResolvedFrom != "" {
		fmt.Fprintf(&b, "- Repository target resolved from: %s\n", in.Provenance.ResolvedFrom)
	}
	fmt.Fprintf(&b, "- Provider: %s\n", providerName)
	fmt.Fprintf(&b, "\nNothing here is merged by ARGUS. The decision, the actor and this pull request are recorded in ARGUS's audit chain.\n")
	return b.String()
}

func backticked(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, "`"+p+"`")
	}
	return out
}

// BranchName expands §11.1's `fixBranch.pattern` ("argus/fix-{incidentId}").
//
// Kept here rather than in the API handler because the pattern is stored on the
// binding and the substitution is part of this package's contract with it. An
// empty or placeholder-free pattern falls back to the documented default rather
// than producing one branch name for every incident, which would collide on the
// second incident and read as "branch already exists".
func BranchName(pattern, incidentID string) string {
	if !strings.Contains(pattern, "{incidentId}") {
		pattern = "argus/fix-{incidentId}"
	}
	return strings.ReplaceAll(pattern, "{incidentId}", incidentID)
}

// objectScope is the "{namespace}/{name}" (or bare name, or "repository")
// scope string §11.1's title/commit-message templates use. One
// implementation shared by pullRequestTitle, commitMessage and
// atomicCommitMessage, which must not drift from each other: a reviewer
// reading a PR title and the commit it points at is reading the same claim
// about the same object twice.
func objectScope(o ObjectRef) string {
	where := o.Name
	if o.Namespace != "" {
		where = o.Namespace + "/" + o.Name
	}
	if where == "" {
		where = "repository"
	}
	return where
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
