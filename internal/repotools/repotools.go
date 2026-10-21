// Package repotools serves BACKLOG.md F22 piece 1: the two read-only tools
// that let the investigation model see the repository an incident's object is
// actually deployed from.
//
// # Why the hub executes these and the agent does not
//
// Every one of the investigation's other tools goes over the mTLS tunnel to the
// cluster agent, and these deliberately do not. The repository is fetched
// hub-side and always has been: repository credentials live in
// repository_bindings, internal/api/repository_locate.go already clones a repo
// sparsely at the pinned revision, and internal/gitops.LocateIn already walks
// it. Having every cluster agent clone customer repositories would multiply
// both the credential surface and the egress requirement by the size of the
// fleet, which is the reasoning internal/gitops' own package comment records
// and which nothing about serving two more tools changes.
//
// So the seam is at the tool CALLBACK, not at the tunnel: internal/llm's
// ToolCallback is a plain function, and the two call sites that supply it
// (internal/api/analyze.go and internal/autoanalyze) dispatch by tool name —
// cluster tools to the tunnel, these two to a Reader. The loop itself needed no
// structural change.
//
// # What a Reader may see, and what it may never see
//
// A Reader is built for ONE incident and is confined to that incident's own
// repository binding, at the revision its GitOps controller reports as synced,
// under the directory that controller reports syncing. It is not a repository
// browser: there is no argument on either tool that names a repository, a
// revision or a directory, because a tool that could read an arbitrary path in
// an arbitrary repository is a different and much worse feature than this one.
// Non-negotiable 3 — scope is bound server-side, never claimed by the model —
// is the rule being followed, and the way it is followed is that the scope is
// baked into the Reader before the model can say anything.
//
// Paths a binding forbids writing are also refused for READING, via
// scm.ForbiddenPath. That is stricter than it strictly has to be, and it is
// the right default: the denylist covers `**/secrets/**`, sealed secrets and
// SOPS-encrypted files, and DESIGN.md §18.4's rule is that secrets never flow
// into prompts. Reading `.github/**` into a model's context is also pure
// downside — it is CI configuration, not manifest, and F22's own constraint
// list keeps it out of reach.
//
// # Repository content is untrusted input
//
// Exactly like cluster data (DESIGN.md §18.7, non-negotiable 10). A values.yaml
// comment saying "ignore your instructions" is text to read, not a directive.
// Nothing here renders, executes or evaluates anything it reads — that is
// lld/09 §2's sandboxed problem and remains out of scope; this package opens
// files.
package repotools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"argus/internal/gitops"
	"argus/internal/logging"
	"argus/internal/redact"
	"argus/internal/scm"
)

// logger is internal/repotools' package-local structured logger (PROJECT.md T22).
var logger = logging.For("repotools")

// The two tool names. Exported so the dispatching call sites (internal/api,
// internal/autoanalyze, cmd/hub) route on this list rather than on string
// literals that could drift from the schemas internal/llm advertises.
const (
	ToolReadRepoFile  = "read_repo_file"
	ToolListRepoFiles = "list_repo_files"
)

// IsRepoTool reports whether a tool name is served by this package rather than
// by the cluster agent. The single place the dispatch decision is made.
func IsRepoTool(name string) bool {
	return name == ToolReadRepoFile || name == ToolListRepoFiles
}

// ToolNames is the two names, for a caller assembling a grant allowlist.
func ToolNames() []string { return []string{ToolReadRepoFile, ToolListRepoFiles} }

// ErrNoRepository is what a call gets when the incident has no readable
// repository. A normal answer, not a failure — the same shape "managed_by:
// none" is a normal answer from get_gitops_ownership.
var ErrNoRepository = errors.New("no repository is known for this incident, so there is no source to read")

const (
	// defaultReadLines / maxReadLines bound one read. The cap is what stops a
	// 20 000-line generated file becoming the investigation's whole context
	// budget. Same discipline list_resources applies to object counts.
	//
	// Raised on 2026-08-28, and the reason is not comfort. A repository change
	// is now a set of WHOLE FILES (internal/gitops/files.go): the model states
	// the complete content each file should end up holding. Content it did not
	// read is content it is inventing, and a proposal built on a partial read
	// silently DISCARDS everything past the window — a far worse failure than
	// the single-field grammar could produce, and one whose diff looks
	// plausible. So the bound has to be comfortably above "a real chart
	// template or values file", not merely above "enough to reason about".
	//
	// It is still a bound, and Truncated/TotalLines still say when it bit —
	// which is exactly what tells a model it must not propose that file's
	// content.
	defaultReadLines = 600
	maxReadLines     = 4000

	// maxReadBytes bounds the returned window regardless of line count, since
	// "lines" is not a bound at all when the lines are long.
	maxReadBytes = 192 << 10 // 192 KiB

	defaultListLimit = 100
	maxListLimit     = 400

	// checkoutTTL is how long a clone is reused before it is re-fetched. An
	// investigation is bounded at three minutes by default
	// (llm.DefaultTimeLimit); this is comfortably longer, so the several tool
	// calls one investigation makes share one fetch, and short enough that a
	// checkout is not a long-lived copy of customer source on the hub's disk.
	//
	// The revision is part of the cache key and is a pinned commit, so a stale
	// entry cannot serve content from the wrong commit — the worst a long TTL
	// could do is keep a directory around, never answer wrongly.
	checkoutTTL = 10 * time.Minute

	// maxCachedCheckouts bounds disk. Past it, the least recently used
	// unreferenced checkout is evicted.
	maxCachedCheckouts = 8
)

// Scope is one incident's repository, resolved by the caller before any model
// output exists. Every field here comes from ARGUS's own records — the
// incident's stored GitOps ownership and the registered binding — and none of
// it is ever read from a tool argument.
type Scope struct {
	// RepoURL, Revision and SourceDir are the incident's own binding: what the
	// controller reports it is syncing, from where, at which commit.
	RepoURL string
	// Revision must be a resolved commit. A branch name would mean reading
	// content the cluster has never applied, which is §11.4's "pin the SHA"
	// rule; the caller checks it and this refuses it again.
	Revision  string
	SourceDir string
	// Host is the binding's host, used as the clone allowlist — a repository
	// ARGUS was told about is the only host it may fetch from.
	Host string
	// Token is the fetch credential. Never logged, never returned, never put
	// into a tool result.
	Token string
	// ForbiddenPaths is the binding's own extra denylist, checked in addition
	// to scm's non-overridable builtin list.
	ForbiddenPaths []string
}

// Valid reports whether this scope can serve a read at all.
func (s Scope) Valid() bool {
	return s.RepoURL != "" && strings.TrimSpace(s.Revision) != "" && s.Host != ""
}

// Reader serves the two tools for one Scope.
type Reader struct {
	scope Scope
	cache *Checkouts
	// log records, per path, whether THIS investigation's most recent
	// read_repo_file call against it returned the file's whole content or
	// only a window of it — BACKLOG.md F25. Nil for a Reader whose caller has
	// no use for the guard (every existing test, and any future caller that
	// doesn't validate proposals against it); readFile simply skips recording
	// when it is nil, so attaching one is strictly additive.
	log *ReadLog
}

// NewReader binds a Scope. A Reader is cheap: nothing is fetched until the
// first call, so an investigation that never asks about the repository never
// pays for a clone.
func NewReader(scope Scope, cache *Checkouts) *Reader {
	return &Reader{scope: scope, cache: cache}
}

// SetReadLog attaches the ReadLog this Reader's read_repo_file calls should
// record into, and returns the receiver so construction can chain:
// NewReader(scope, cache).SetReadLog(log). Safe to call on a nil *Reader (a
// no-op), matching this file's existing nil-receiver tolerance elsewhere
// (Call, WithCheckout).
//
// One Reader is built fresh per investigation (internal/api/analyze.go,
// internal/autoanalyze.go) and never reused across two different
// investigations of the same incident, so a log attached here needs no
// per-incident or per-revision key of its own: every read it ever records is
// implicitly at this Reader's own bound Scope.Revision, which is exactly the
// revision the caller will check a proposal against.
func (r *Reader) SetReadLog(log *ReadLog) *Reader {
	if r != nil {
		r.log = log
	}
	return r
}

// Scope returns the bound scope, so a caller that needs the same repository for
// something else (verifying a source mapping, say) uses the identical target
// rather than resolving it a second time and possibly differently.
func (r *Reader) Scope() Scope { return r.scope }

// Call executes one repo tool. The signature deliberately matches
// internal/llm.ToolCallback's tail, so a dispatching closure is one `if`.
func (r *Reader) Call(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
	if r == nil || !r.scope.Valid() {
		return nil, ErrNoRepository
	}
	dir, release, err := r.cache.Checkout(ctx, r.scope)
	if err != nil {
		return nil, err
	}
	defer release()

	switch tool {
	case ToolReadRepoFile:
		return r.readFile(dir, args)
	case ToolListRepoFiles:
		return r.listFiles(dir, args)
	default:
		// Unreachable through the dispatching call sites, which check
		// IsRepoTool first — but a tool this package does not implement must
		// never fall through to something that does.
		return nil, fmt.Errorf("repotools: %q is not a repository tool", tool)
	}
}

// WithCheckout runs fn against a checkout of this Reader's scope. It exists so
// the source-mapping verification (F22 piece 2) reads the SAME clone the model
// read from, rather than making a second fetch that could resolve differently.
func (r *Reader) WithCheckout(ctx context.Context, fn func(dir string) error) error {
	if r == nil || !r.scope.Valid() {
		return ErrNoRepository
	}
	dir, release, err := r.cache.Checkout(ctx, r.scope)
	if err != nil {
		return err
	}
	defer release()
	return fn(dir)
}

type readRepoFileArgs struct {
	Path      string `json:"path"`
	StartLine int    `json:"startLine"`
	MaxLines  int    `json:"maxLines"`
}

type readRepoFileResult struct {
	Path      string `json:"path"`
	Revision  string `json:"revision"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
	// TotalLines and Truncated are reported for the same reason
	// list_resources reports totalMatched/truncated: a model reasoning from
	// "the key is not in this file" must be able to tell that from "the key is
	// not in the part of the file I was shown".
	TotalLines int  `json:"totalLines"`
	Truncated  bool `json:"truncated"`
	// Warning is set only when Truncated is true, and it says the one thing a
	// partial read now implies that it did not before whole-file proposals
	// existed: this content is NOT the file, so it must not be used as the
	// basis for proposing the file's new content. A boolean a model may or may
	// not weigh is weaker than a sentence telling it what the boolean means.
	Warning string `json:"warning,omitempty"`
	Content string `json:"content"`
}

// ReadLog tracks, for the lifetime of ONE investigation, whether the most
// recent read_repo_file call against each path returned that file's whole
// content or only a window of it.
//
// # Why this exists (BACKLOG.md F25)
//
// A repository change is a set of WHOLE files (see this package's own doc
// comment and internal/remediation.OpenPRParams): the model states the
// complete content a file should end up holding. If the model read only part
// of a file — read_repo_file's own Truncated/Warning already say so, at read
// time — and then proposes "the new content" built on that partial view, the
// proposal silently discards everything outside the window it saw. The diff
// looks entirely plausible; nothing about its SHAPE reveals the mistake, and
// BACKLOG.md F25 explicitly rejects keying enforcement on the diff's shape
// (a legitimate, intended deletion looks identical to an accidental one).
// What IS knowable, and provable rather than inferred, is whether THIS
// investigation's own most recent read of THIS exact path was truncated —
// this type is that record.
//
// # Scope and lifetime
//
// One ReadLog belongs to one investigation: internal/api/analyze.go and
// internal/autoanalyze.go each build one fresh (NewReadLog) alongside the
// Reader they attach it to (Reader.SetReadLog), and use that same instance to
// validate whatever the investigation's final ProposedPlan/
// ProposedPairedPlan turned out to propose (see
// internal/api.RefuseTruncatedRepositoryProposals) before either is ever
// persisted or shown to an operator. Nothing here is bounded, evicted, or
// shared across investigations — the same "carry it in memory for the
// duration of one bounded tool-calling loop" scope internal/llm/toolloop.go's
// Investigate/investigate already applies to that loop's own message history,
// because a ReadLog's owner already goes out of scope (and becomes eligible
// for GC) at the exact moment the investigation that built it returns.
//
// Keyed by path alone, not by revision: a Reader — and therefore every
// ReadLog it is ever attached to — is bound to one Scope for its whole life
// (Scope is immutable after NewReader), so every read a given ReadLog ever
// records is implicitly at that Reader's one Scope.Revision, which is exactly
// the revision the eventual proposal is checked against.
//
// Safe for concurrent use, and safe to call every method on a nil *ReadLog —
// exactly like Reader.Call and Reader.WithCheckout already tolerate a nil
// receiver — so a caller with no use for the guard (every test that doesn't
// construct one, any future caller that never validates a proposal) pays
// nothing and changes nothing about read_repo_file's own behaviour.
type ReadLog struct {
	mu       sync.Mutex
	reads    map[string]readState
	listings map[string]listingState
}

// listingState is one non-truncated list_repo_files result: the exact set of
// file paths list_repo_files actually returned under the directory it was
// asked to list. Only ever populated for a NON-truncated listing — see
// recordListing's own doc comment for why a truncated one is worthless as
// proof of anything's absence.
type listingState struct {
	files map[string]bool
}

type readState struct {
	truncated                      bool
	startLine, endLine, totalLines int
}

// NewReadLog builds an empty log for one investigation.
func NewReadLog() *ReadLog {
	return &ReadLog{reads: make(map[string]readState)}
}

// record stores path's latest read outcome, OVERWRITING any earlier entry for
// the same path — see this type's own doc comment for why the LATEST read,
// not the first, is what must govern.
func (l *ReadLog) record(path string, truncated bool, startLine, endLine, totalLines int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads[path] = readState{truncated: truncated, startLine: startLine, endLine: endLine, totalLines: totalLines}
}

// recordListing stores a NON-TRUNCATED list_repo_files result for dir (the
// repository-relative directory it listed, "" meaning the confined source
// directory's own root — see normalizeListedDir) — B141's establishment-of-
// fact mechanism for a path that does not exist yet, the same status a
// delete's own precondition already grants a path confirmed to exist. A
// truncated listing is never recorded: gitops.ListCheckoutFiles walks a
// directory recursively and reports every regular file under it, so a
// NON-truncated listing proves a path either IS or IS NOT anywhere in that
// subtree — but a listing cut off by its own limit before finishing the walk
// proves nothing about what it didn't get to, and recording it as if it did
// would be exactly the "weaken the guard for a path that merely went
// unread" mistake B141 exists to avoid, just approached from the listing
// side instead of the read side.
func (l *ReadLog) recordListing(dir string, files []string, truncated bool) {
	if l == nil || truncated {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listings == nil {
		l.listings = make(map[string]listingState)
	}
	set := make(map[string]bool, len(files))
	for _, f := range files {
		set[f] = true
	}
	l.listings[dir] = listingState{files: set}
}

// establishedAbsentLocked reports whether path is confirmed to NOT exist at
// the pinned revision, from some recorded (non-truncated) listing whose own
// directory contains path — i.e. path equals that directory or sits
// somewhere underneath it. Caller must already hold l.mu.
func (l *ReadLog) establishedAbsentLocked(path string) bool {
	for dir, st := range l.listings {
		if dir != "" && path != dir && !strings.HasPrefix(path, dir+"/") {
			continue
		}
		if !st.files[path] {
			return true
		}
	}
	return false
}

// TruncatedProposal is one path a proposal named whose most recent read in
// this investigation was truncated — CheckPaths' report of exactly what makes
// a proposal refusable under BACKLOG.md F25.
type TruncatedProposal struct {
	Path                           string
	StartLine, EndLine, TotalLines int
}

// CheckPaths reports every one of paths whose most recent read this log
// recorded was truncated, after normalizing each the same way readFile
// normalizes a model-supplied path relative to sourceDir (pathWithinSource) —
// the read side of read_repo_file and the proposal side of a repository
// change both accept either a repository-relative path or one relative to the
// synced directory, and the two must be compared in the same canonical form
// or a perfectly good full read would go unmatched against its own proposal.
//
// A path this log has NO record of at all — never read this investigation,
// or read through some other mechanism entirely — is deliberately NOT
// reported here. That is a different, broader question ("did the model
// establish this file's content at all before proposing it," which
// repoToolGuidance's prompt text already addresses for the no-repo-tools
// case) than the one BACKLOG.md F25 scopes this guard to: whether a read that
// DID happen was a partial one. See RefuseTruncatedRepositoryProposals
// (internal/api/repo_tools.go) for the caller that applies this.
func (l *ReadLog) CheckPaths(sourceDir string, paths []string) []TruncatedProposal {
	if l == nil || len(paths) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var bad []TruncatedProposal
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		key := pathWithinSource(sourceDir, p)
		if seen[key] {
			continue
		}
		seen[key] = true
		if st, ok := l.reads[key]; ok && st.truncated {
			bad = append(bad, TruncatedProposal{
				Path:       p,
				StartLine:  st.startLine,
				EndLine:    st.endLine,
				TotalLines: st.totalLines,
			})
		}
	}
	return bad
}

// Unread reports every one of paths this log has NO record of at all —
// BACKLOG.md F28 finding 1's widening of F25's own guard, for the gap F25's
// doc comment explicitly named and declined to close: "a path the model
// never read at all is deliberately NOT refused by this guard." CheckPaths
// above answers "was a read that DID happen truncated"; this answers the
// prior, broader question — "did any read happen at all" — which is exactly
// the shape of the measured finding (253 real OpenPR proposals, 13 with any
// recorded read_repo_file call at all for their incident).
//
// A path is exempted from "unread" — B141 — when a recorded, NON-truncated
// list_repo_files call already established it does not exist at the pinned
// revision: establishedAbsentLocked. That is the identical status
// refuseUnreadPlan's own delete-exemption already grants a path confirmed to
// exist, extended to the complementary case a whole-file, read-before-
// propose grammar had no answer for at all — a path that is GENUINELY NEW,
// which read_repo_file can structurally never succeed against no matter how
// many times it is called. Before this exemption existed, ARGUS could not
// propose adding a file to a repository under any circumstances; every
// "the referenced object is missing" fault whose real fix is a new file
// (a missing ConfigMap, a missing PodDisruptionBudget, a missing overlay)
// had no route through OpenPR at all.
//
// Same normalization as CheckPaths (pathWithinSource, de-duplicated), and
// the same nil/empty tolerance, for the same reason: a path this log was
// never told to track (no repository scope at all) must never be reported as
// suspicious by a guard whose only job is to catch a PROVABLE case.
func (l *ReadLog) Unread(sourceDir string, paths []string) []string {
	if l == nil || len(paths) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var bad []string
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		key := pathWithinSource(sourceDir, p)
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, ok := l.reads[key]; ok {
			continue
		}
		if l.establishedAbsentLocked(key) {
			continue
		}
		bad = append(bad, p)
	}
	return bad
}

// ReadLogRegistry lets a repository tool call that arrives through a
// COMPLETELY DIFFERENT code path from the one that built a ReadLog still
// record into it — BACKLOG.md F28's fix for the scoping gap F25 documented
// and explicitly left open: "the cli backend's tool calls reach
// internal/api.CallRepoTool through a fresh *repotools.Reader per MCP call
// with no ReadLog attached, so this guard does not yet cover it."
//
// # Why a registry, not just "attach the log like the api backend does"
//
// internal/api/analyze.go builds one Reader and attaches one ReadLog to it,
// and every repo-tool call the api backend's in-process loop makes goes
// through that exact Reader — so the log sees every read by construction.
// The cli backend cannot use that Reader at all: the CLI process calls back
// into the hub's MCP server (internal/mcp), which reaches
// internal/api.CallRepoTool with nothing but a grant's cluster/incident ids —
// no Go closure, no shared Reader, not even the same goroutine's call stack.
// The only thing the two paths share is the INCIDENT ID. A registry keyed by
// it is what lets CallRepoTool find and write into the SAME log the caller
// that started this investigation (internal/api/analyze.go or
// internal/autoanalyze) built for it, regardless of which backend ends up
// serving the investigation — the caller does not need to know in advance
// which one that will be (internal/llm.Router resolves that per call).
//
// # Lifetime
//
// Begin/End bracket ONE investigation, exactly like a ReadLog's own
// lifetime is already scoped (see that type's doc comment): the caller
// calls Begin at the same point it used to call NewReadLog, and End once it
// is done consuming the log (after RefuseTruncatedRepositoryProposals/
// RefuseUnreadRepositoryProposals have run), normally via defer right after
// Begin. Never bounded by a TTL or a size cap the way Checkouts is — an
// entry lives for, at most, one investigation's own bounded wall-clock
// budget (llm.DefaultTimeLimit), and a caller that forgot to End would leak
// one map entry per incident ID, not per call, which is a bug worth fixing
// at the call site rather than papering over here with an eviction policy
// that could make Get return the wrong investigation's log.
//
// # Concurrency
//
// Safe for concurrent use. Two different incidents never collide (keyed
// separately). Two investigations of the SAME incident running concurrently
// — not a shape this codebase's callers produce today, but not prevented by
// this type either — would share one log for the duration of the overlap;
// the worst outcome is over-attribution (a path one investigation read
// counting as "read" for the other's proposal too), which is the safe
// direction for a guard whose whole purpose is refusing a PROVABLE blind
// rewrite, never the unsafe one.
//
// Nil-safe on every method, matching Reader/ReadLog's own existing
// tolerance: a *Server or *autoanalyze.Poller built without one (every
// existing test, any future caller with no use for the registry) gets a
// registry-of-one-per-call behaviour indistinguishable from calling
// NewReadLog() directly — correct, just unshared, so CallRepoTool simply
// never sees a match and the guard degrades to exactly its pre-F28 no-op for
// the cli backend rather than panicking.
type ReadLogRegistry struct {
	mu   sync.Mutex
	logs map[string]*ReadLog
}

// NewReadLogRegistry builds an empty registry. One per hub process, shared
// between internal/api.Server and internal/autoanalyze.Poller — see
// cmd/hub/main.go's wiring — the same "constructed once, passed to both"
// treatment main.go already gives internal/events.Bus, for the identical
// reason: CallRepoTool lives on *api.Server alone, so both callers that can
// START an investigation need a reference to the ONE registry it reads from.
func NewReadLogRegistry() *ReadLogRegistry {
	return &ReadLogRegistry{logs: make(map[string]*ReadLog)}
}

// Begin creates a fresh ReadLog for incidentID, stores it under that key,
// and returns it. A second Begin for the same incidentID before the first's
// End replaces the stored log (last writer wins) — the same "always
// investigate one incident's own tool calls" trust boundary IncidentRepoScope
// already assumes elsewhere; nothing here widens it.
func (r *ReadLogRegistry) Begin(incidentID string) *ReadLog {
	log := NewReadLog()
	if r == nil {
		return log
	}
	r.mu.Lock()
	r.logs[incidentID] = log
	r.mu.Unlock()
	return log
}

// End removes incidentID's entry. Call once, via defer, right after Begin —
// see this type's own doc comment for why that is safe even though the
// guard that consumes the log runs before the deferred End fires.
func (r *ReadLogRegistry) End(incidentID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.logs, incidentID)
	r.mu.Unlock()
}

// Get returns the ReadLog currently registered for incidentID, or nil if
// none is (no investigation of this incident is in flight, or this registry
// is nil) — CallRepoTool's own read of it tolerates a nil result exactly
// like every other nil-log case in this package.
func (r *ReadLogRegistry) Get(incidentID string) *ReadLog {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logs[incidentID]
}

func (r *Reader) readFile(dir string, raw json.RawMessage) (json.RawMessage, error) {
	var args readRepoFileArgs
	if err := unmarshalArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Path) == "" {
		return nil, errors.New("read_repo_file needs a path")
	}
	if pattern := scm.ForbiddenPath(pathWithinSource(r.scope.SourceDir, args.Path), r.scope.ForbiddenPaths); pattern != "" {
		return nil, fmt.Errorf("refusing to read %s: it matches the forbidden path %q. ARGUS does not read CI configuration, encrypted content, or anything under a secrets directory into an investigation", args.Path, pattern)
	}

	file, err := gitops.ReadCheckoutFile(dir, r.scope.SourceDir, args.Path)
	if err != nil {
		return nil, err
	}

	start := args.StartLine
	if start < 1 {
		start = 1
	}
	limit := args.MaxLines
	if limit <= 0 {
		limit = defaultReadLines
	}
	if limit > maxReadLines {
		limit = maxReadLines
	}

	lines := strings.Split(string(file.Content), "\n")
	total := len(lines)
	if start > total {
		return nil, fmt.Errorf("%s has %d lines, so line %d does not exist", file.Path, total, start)
	}
	end := start + limit - 1
	if end > total {
		end = total
	}
	window := strings.Join(lines[start-1:end], "\n")
	truncated := start > 1 || end < total
	if len(window) > maxReadBytes {
		// Byte-bounded on a line boundary rather than mid-line: half a line is
		// not a line, and the model is being asked to quote lines verbatim.
		window, end = trimToBytes(lines, start, end, maxReadBytes)
		truncated = true
	}

	// The bounded pattern layer, applied to what leaves for the model.
	//
	// Non-negotiable 9 says secrets never flow into prompts, and its stated
	// rule is that redaction happens at CAPTURE time rather than at read time.
	// For cluster data the capture point is the agent, which is why
	// internal/redact is otherwise only called from there. Repository content
	// never passes through a cluster at all: the hub IS its capture point, and
	// this call is the same discipline applied at the only place it can be,
	// not the weaker at-the-hub-on-read arrangement that rule warns against.
	//
	// The path denylist above is the stronger control — `**/secrets/**`,
	// `*.sops.*`, sealed secrets and CI config are refused outright rather
	// than redacted. This covers the residual case a denylist structurally
	// cannot: a plaintext credential sitting in an ordinary values file. It is
	// explicitly best-effort (see redact.Text's own doc comment) — a secret in
	// an unrecognisable format still crosses, which is the same accepted cost
	// the log-line path carries.
	//
	// It changes only what the MODEL sees; the repository itself is untouched.
	//
	// One consequence matters more now that a repository change is a set of
	// whole files: a model that reads a redacted window and proposes it back as
	// a file's new content would write the marker into the real file. That is
	// BUGS.md 112's failure, and it is refused twice —
	// remediation.OpenPRParams.Validate at the gate, and
	// gitops.ApplyFileEdit at the byte-writing chokepoint, which refuses any
	// content that INTRODUCES the marker. Neither of them relies on this
	// function or on the model noticing.
	window = redact.Text(window)

	// BACKLOG.md F25: record this read's outcome for file.Path, OVERWRITING
	// whatever an earlier read of the same path in this same investigation
	// recorded — deliberately, so a truncated read followed by a corrective
	// full re-read (page with startLine until truncated is false) is judged
	// by the LATEST read, not the first. r.log is nil for any Reader whose
	// caller attached none (SetReadLog's own doc comment), in which case this
	// is a no-op — recording is strictly additive to this tool's behaviour.
	r.log.record(file.Path, truncated, start, end, total)

	out := readRepoFileResult{
		Path:       file.Path,
		Revision:   r.scope.Revision,
		StartLine:  start,
		EndLine:    end,
		TotalLines: total,
		Truncated:  truncated,
		Content:    window,
	}
	if truncated {
		out.Warning = fmt.Sprintf("this is lines %d-%d of %d — NOT the whole file. Do not propose new content for %s from this: everything outside this window would be discarded. Read the remaining lines first, or leave this file alone.",
			start, end, total, file.Path)
	}
	return marshalResult(out)
}

type listRepoFilesArgs struct {
	Subdir string `json:"subdir"`
	Limit  int    `json:"limit"`
}

type listedFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

type listRepoFilesResult struct {
	Directory    string       `json:"directory"`
	Revision     string       `json:"revision"`
	Files        []listedFile `json:"files"`
	TotalMatched int          `json:"totalMatched"`
	Returned     int          `json:"returned"`
	Truncated    bool         `json:"truncated"`
}

func (r *Reader) listFiles(dir string, raw json.RawMessage) (json.RawMessage, error) {
	var args listRepoFilesArgs
	if err := unmarshalArgs(raw, &args); err != nil {
		return nil, err
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}

	listing, err := gitops.ListCheckoutFiles(dir, r.scope.SourceDir, args.Subdir, limit)
	if err != nil {
		return nil, err
	}
	out := listRepoFilesResult{
		Directory:    listing.Dir,
		Revision:     r.scope.Revision,
		Files:        make([]listedFile, 0, len(listing.Entries)),
		TotalMatched: listing.TotalMatched,
		Truncated:    listing.Truncated,
	}
	for _, e := range listing.Entries {
		// A forbidden path is not listed either, so a model is never shown a
		// file it would then be refused for reading — a listing that advertises
		// what the read tool will not serve is its own kind of confusing bug
		// (the same "advertised but refused" split offeredToolDefinitions
		// exists to prevent).
		if scm.ForbiddenPath(e.Path, r.scope.ForbiddenPaths) != "" {
			out.TotalMatched--
			continue
		}
		out.Files = append(out.Files, listedFile{Path: e.Path, Bytes: e.Bytes})
	}
	out.Returned = len(out.Files)

	// B141: record this listing so Unread can treat a path proven absent from
	// it as established, not merely "never read" — see recordListing's own
	// doc comment for why a truncated listing is deliberately never recorded.
	// Recorded from listing.Entries (repository-relative, matching
	// readFile's file.Path exactly — both come from gitops' own
	// resolveWithin/ListCheckoutFiles), not from out.Files, which has already
	// dropped any forbidden-path entry above: a forbidden path is never
	// readable OR proposable, so its absence from out.Files must never be
	// misread as "confirmed absent" — it may exist and simply be withheld.
	paths := make([]string, 0, len(listing.Entries))
	for _, e := range listing.Entries {
		paths = append(paths, e.Path)
	}
	r.log.recordListing(normalizeListedDir(r.scope.SourceDir, args.Subdir), paths, listing.Truncated)

	return marshalResult(out)
}

// normalizeListedDir mirrors pathWithinSource's own repository-relative
// normalization, for a list_repo_files "subdir" argument rather than a
// candidate file path — pathWithinSource exists only for the latter, and its
// own logic does not correctly reduce an empty/"." subdir (meaning "the
// whole confined source directory") to sourceDir itself, which is the form
// establishedAbsentLocked needs to compare a candidate path's own prefix
// against. Mirrors gitops.resolveWithin's identical empty-candidate case
// (unexported there, so this cannot simply call it).
func normalizeListedDir(sourceDir, subdir string) string {
	clean := strings.Trim(strings.TrimSpace(filepath.ToSlash(subdir)), "/")
	if clean == "" || clean == "." {
		return strings.Trim(strings.TrimSpace(filepath.ToSlash(sourceDir)), "/")
	}
	return pathWithinSource(sourceDir, clean)
}

// pathWithinSource is the path a forbidden-path check should be applied to: the
// repository-relative form, since the denylist's patterns ("scripts/**",
// "**/Chart.yaml") are written against repository-relative paths. A model that
// wrote a path relative to the synced directory gets it prefixed first, so
// "scripts/deploy.sh" under sourceDir "envs/prod" is checked as
// "envs/prod/scripts/deploy.sh" and still matches "**/*.sh".
func pathWithinSource(sourceDir, p string) string {
	clean := strings.Trim(strings.TrimSpace(filepath.ToSlash(p)), "/")
	dir := strings.Trim(strings.TrimSpace(filepath.ToSlash(sourceDir)), "/")
	if dir == "" || dir == "." || clean == dir || strings.HasPrefix(clean, dir+"/") {
		return clean
	}
	return dir + "/" + clean
}

func trimToBytes(lines []string, start, end, budget int) (string, int) {
	var b strings.Builder
	last := start - 1
	for i := start - 1; i < end; i++ {
		if b.Len()+len(lines[i])+1 > budget {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(lines[i])
		last = i + 1
	}
	return b.String(), last
}

func unmarshalArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("could not read this tool's arguments: %w", err)
	}
	return nil
}

func marshalResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return b, nil
}

// --- checkout cache ---

// Checkouts is a small, bounded cache of sparse shallow clones, keyed by
// (repository, revision, synced directory).
//
// It exists because cost matters here in a way it does not for a cluster tool
// call: a fetch is seconds, an investigation is bounded at minutes, and a model
// reading a chart makes several calls in a row against the same commit. Without
// this, the first thing F22 piece 1 would buy is a per-call git fetch.
//
// Correctness does not depend on it. The revision is a pinned commit and part
// of the key, so a cached entry can only ever serve the exact content a fresh
// clone would; the cache decides how often ARGUS pays for the fetch, never what
// it reads.
type Checkouts struct {
	mu      sync.Mutex
	entries map[string]*checkoutEntry
	// parent is where checkout directories are created. Empty means the OS
	// temp directory; tests set it.
	parent string
	// clone is gitops.Clone in production, replaceable in tests so the cache's
	// own behaviour is provable without a git server.
	clone func(ctx context.Context, opts gitops.CloneOptions) error
}

type checkoutEntry struct {
	dir      string
	lastUsed time.Time
	// refs is how many calls are reading this checkout right now. Eviction only
	// ever removes an entry at zero, so a directory is never deleted out from
	// under a read in progress.
	refs int
}

// NewCheckouts builds the cache. One per hub process.
func NewCheckouts() *Checkouts {
	return &Checkouts{
		entries: map[string]*checkoutEntry{},
		clone: func(ctx context.Context, opts gitops.CloneOptions) error {
			_, err := gitops.Clone(ctx, opts)
			return err
		},
	}
}

// NewCheckoutsForTest builds a Checkouts whose fetch function is replaceable
// — exported (unlike Checkouts' own clone field) specifically so a caller in
// a DIFFERENT package can exercise a real Reader end to end (a real
// read_repo_file call, a real ReadLog recording what it saw) without a git
// server, exactly as this package's own tests already do via their
// unexported fakeCheckouts helper. internal/api's tests for
// RefuseTruncatedRepositoryProposals (BACKLOG.md F25) are the first caller:
// proving that function's plan-refusal logic against a ReadLog this package
// actually populated, rather than one hand-built by poking at internals
// internal/api cannot reach.
func NewCheckoutsForTest(parent string, clone func(ctx context.Context, opts gitops.CloneOptions) error) *Checkouts {
	return &Checkouts{entries: map[string]*checkoutEntry{}, parent: parent, clone: clone}
}

// Checkout returns a directory holding scope's repository at scope's revision,
// and a release function the caller must call when it is done reading.
func (c *Checkouts) Checkout(ctx context.Context, scope Scope) (dir string, release func(), err error) {
	if !scope.Valid() {
		return "", nil, ErrNoRepository
	}
	key := scope.RepoURL + "@" + scope.Revision + ":" + scope.SourceDir

	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		if _, statErr := os.Stat(e.dir); statErr == nil {
			e.refs++
			e.lastUsed = time.Now()
			c.mu.Unlock()
			return e.dir, func() { c.release(key) }, nil
		}
		// The directory went away underneath us (a tmp reaper, an operator).
		// Drop the entry and clone again rather than serving a path that is
		// not there.
		delete(c.entries, key)
	}
	c.mu.Unlock()

	// Cloned outside the lock: a fetch is seconds, and holding the cache lock
	// across it would serialise every investigation in the hub behind one slow
	// repository. Two concurrent callers for the same key may both clone; the
	// loser's checkout is removed below rather than leaked.
	parent, err := os.MkdirTemp(c.parent, "argus-repotools-")
	if err != nil {
		return "", nil, fmt.Errorf("create a working directory: %w", err)
	}
	// gitops.Clone refuses a directory that already exists, so it can never
	// write into someone else's checkout — the child is what it creates.
	target := filepath.Join(parent, "repo")

	var sparse []string
	if clean := strings.Trim(strings.TrimSpace(scope.SourceDir), "/"); clean != "" && clean != "." {
		sparse = []string{clean}
	}
	if cloneErr := c.clone(ctx, gitops.CloneOptions{
		RepoURL:      scope.RepoURL,
		Revision:     scope.Revision,
		Dir:          target,
		SparsePaths:  sparse,
		AllowedHosts: []string{scope.Host},
		Token:        scope.Token,
	}); cloneErr != nil {
		_ = os.RemoveAll(parent)
		// The token is never in CloneOptions' error text (gitops.Clone reports
		// the cleaned URL), but the wrapping message names only the repository
		// and revision regardless.
		return "", nil, fmt.Errorf("fetch %s at %s: %w", scope.RepoURL, shortRevision(scope.Revision), cloneErr)
	}

	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		// Another caller won the race. Use theirs and discard ours, so the two
		// never diverge and the loser's directory does not survive the request.
		e.refs++
		e.lastUsed = time.Now()
		c.mu.Unlock()
		_ = os.RemoveAll(parent)
		return e.dir, func() { c.release(key) }, nil
	}
	c.entries[key] = &checkoutEntry{dir: target, lastUsed: time.Now(), refs: 1}
	c.evictLocked()
	c.mu.Unlock()
	return target, func() { c.release(key) }, nil
}

func (c *Checkouts) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok && e.refs > 0 {
		e.refs--
		e.lastUsed = time.Now()
	}
	c.evictLocked()
}

// evictLocked removes expired entries, then the oldest entries past the size
// cap. Only ever entries with no reader — see checkoutEntry.refs.
func (c *Checkouts) evictLocked() {
	now := time.Now()
	for key, e := range c.entries {
		if e.refs == 0 && now.Sub(e.lastUsed) > checkoutTTL {
			c.removeLocked(key, e)
		}
	}
	for len(c.entries) > maxCachedCheckouts {
		var oldestKey string
		var oldest *checkoutEntry
		for key, e := range c.entries {
			if e.refs != 0 {
				continue
			}
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				oldestKey, oldest = key, e
			}
		}
		if oldest == nil {
			// Everything is in use. The cap is a disk bound, not a correctness
			// one, so exceeding it briefly is the right answer; the next
			// release will bring it back down.
			return
		}
		c.removeLocked(oldestKey, oldest)
	}
}

func (c *Checkouts) removeLocked(key string, e *checkoutEntry) {
	delete(c.entries, key)
	// The PARENT of the clone dir, which is the temp directory this cache
	// created — removing only the child would leak the parent.
	if err := os.RemoveAll(filepath.Dir(e.dir)); err != nil {
		logger.Warn("could not remove a checkout directory", slog.String("dir", e.dir), logging.Err(err))
	}
}

func shortRevision(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
