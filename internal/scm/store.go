package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/outbound"
	"argus/internal/secretbox"
	"argus/internal/settings"
)

// logger is internal/scm's package-local structured logger (PROJECT.md T22).
var logger = logging.For("scm")

// Binding is a registered repository plus the credential that may write to it.
//
// One per repository URL per tenant, enforced by a unique index. Two bindings
// for one repo would mean two credentials could open a PR against it with
// nothing recording which ARGUS used — ambiguity that is far cheaper to forbid
// than to resolve after the fact.
type Binding struct {
	ID       string
	Provider string // "github" | "gitlab"
	URL      string
	// Host is derived from URL at write time, not re-parsed on read, so the
	// stored value is what was validated. It is what an incoming repo URL is
	// checked against — see MatchesHost.
	Host string
	// APIBaseURL is empty for the provider's public API. DESIGN.md §11.3 makes
	// this "required, not optional" for GHES and GitLab CE/EE, which is what
	// makes a self-hosted ARGUS able to reach a customer's internal Git at all.
	APIBaseURL    string
	DefaultBranch string
	CredentialRef string
	// CredentialExpiresAt is advisory and is the reason it is stored at all: a
	// fine-grained token expires, and when it does PR creation simply starts
	// failing. D-R9 requires warning BEFORE the date rather than reporting
	// failures after it, which needs the date to be known.
	CredentialExpiresAt *time.Time
	CreatedAt           time.Time

	// WriteScope and FixBranchPattern come from the binding's stored `spec`
	// (SaveBinding writes DESIGN.md §11.3's RepositoryBinding shape into it).
	// Populated by ProviderFor only — ListBindings deliberately leaves them
	// zero, because a list feeds an API response and nothing in it needs the
	// write policy.
	//
	// These are read rather than re-derived at each use because the whole point
	// of storing the spec is that an operator's configured policy, not a
	// constant compiled into the hub, decides where ARGUS may write and what its
	// branches are called.
	WriteScope WriteScope
	// FixBranchPattern is §11.1's `fixBranch.pattern`, e.g.
	// "argus/fix-{incidentId}". Empty when the binding predates a stored spec;
	// the caller supplies its own default rather than this package inventing one,
	// since the branch name is part of the caller's PR story.
	FixBranchPattern string
	// PullRequestEnabled is §11.1's `pullRequest.enabled`. Defaults to true when
	// the spec says nothing — a binding registered with no spec at all is a
	// binding registered in order to open pull requests, so "absent" must not
	// read as "disabled" and silently make the feature unavailable.
	PullRequestEnabled bool
	// ObjectMappings is BACKLOG.md F19 mechanism 1: an operator's explicit
	// statement of where a plain-Helm or kubectl-applied object's config
	// lives, for the case get_gitops_ownership itself can never resolve (no
	// GitOps controller object exists to read a repo URL from at all — see
	// internal/agent/tools.go's resolveRepoTarget doc comment). Populated by
	// ProviderFor and FindObjectMapping's own scan, same as WriteScope/
	// FixBranchPattern above; ListBindings leaves it zero for the same reason.
	ObjectMappings []ObjectMapping
}

// ObjectMapping is one entry of bindingSpec's `objectMappings` — BACKLOG.md
// F19 mechanism 1, decided 2026-08-25: "Helm release `payments` in `prod` ->
// repo `platform/config`, path `envs/prod/payments`, or the same by label
// selector." Exactly one of the two forms is set per entry:
//
//   - ReleaseName + Namespace: matches a Helm release by name, scoped to the
//     namespace it was installed into — a release name is only unique WITHIN
//     a namespace, so both are required together or the match is ambiguous.
//   - LabelSelector: matches by a set of labels present on the object (or,
//     since a Pod inherits its pod-TEMPLATE labels, effectively on its owning
//     workload too) — the only form that can match a plain `kubectl apply`
//     object, which carries no release name at all.
//
// Path is required in both forms: it is the location within the Binding this
// entry is stored on (its `url`) that the mapping resolves to, e.g. a Helm
// values directory or a plain-manifest directory a pull request would target.
//
// See Validate for the "never both, never neither" rule, and MatchesRelease/
// MatchesLabels for how each form is actually matched against a live object.
//
// Scope is BACKLOG.md F30's multi-cluster correction: without it, an entry
// for "shop-apps in default" matched that release/namespace on EVERY cluster
// in the fleet, which is wrong two different ways — a dev/prod split fed
// from different overlays gets one wrong path for both, and an object
// present on every cluster (kube-system/coredns) goes fleet-wide from a
// single link. The zero value (Type == "") means AllClusters — see
// authz.ScopeIncludesCluster's own comment for why that has to be the
// default rather than a validation error: every mapping written before this
// field existed, and every one written by a caller with no scope picker,
// means exactly what it always did.
type ObjectMapping struct {
	ReleaseName   string            `json:"releaseName,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	LabelSelector map[string]string `json:"labelSelector,omitempty"`
	Path          string            `json:"path"`
	Scope         authz.Scope       `json:"scope,omitempty"`
}

// Validate enforces the "exactly one form, and Path always" rule the write
// path (internal/api/repositories.go's handleCreateRepositoryBinding) must
// reject a malformed entry with, rather than silently storing something that
// can never match anything (a selector-less, release-less entry) or that
// matches ambiguously (both forms at once — which repo/path would even be the
// operator's intent?). Also validates Scope, on the same "reject a malformed
// entry outright rather than store something that can never resolve
// correctly" principle.
func (m ObjectMapping) Validate() error {
	if strings.TrimSpace(m.Path) == "" {
		return errors.New("scm: an object mapping's path is required")
	}
	hasReleaseName := strings.TrimSpace(m.ReleaseName) != ""
	hasNamespace := strings.TrimSpace(m.Namespace) != ""
	hasSelector := len(m.LabelSelector) > 0

	switch {
	case (hasReleaseName || hasNamespace) && hasSelector:
		return errors.New("scm: an object mapping must match EITHER a Helm release (releaseName + namespace) OR a label selector, not both")
	case hasReleaseName != hasNamespace:
		return errors.New("scm: a release-based object mapping needs BOTH releaseName and namespace — a release name is only unique within its own namespace")
	case hasReleaseName && hasNamespace, hasSelector:
		return m.validateScope()
	default:
		return errors.New("scm: an object mapping needs either releaseName + namespace, or a non-empty labelSelector")
	}
}

// validateScope rejects a Scope that Validate must catch before it is ever
// stored — an unrecognised Type, or a Cluster/ClusterGroup scope with no id
// to actually scope to (which authz.ScopeIncludesCluster would otherwise
// silently treat as matching nothing, a confusing way to fail for something
// that looked like it should have worked). Existence of the named cluster/
// group under this tenant is NOT checked here — that needs a database round
// trip Validate's pure-function callers (this package's own tests included)
// do not have, and the two real write paths both already know their id is
// real by construction: the incident-flow confirmation only ever offers ids
// it just read from the tenant's own clusters/cluster_groups, and a hand-typed
// Settings entry gets the same "no such cluster" failure any other bad
// reference would, the first time something tries to resolve it.
func (m ObjectMapping) validateScope() error {
	switch m.Scope.Type {
	case "", "AllClusters":
		if m.Scope.ClusterID != "" || m.Scope.GroupID != "" {
			return errors.New("scm: an AllClusters (or unset) scope must not also name a cluster or cluster group")
		}
		return nil
	case "Cluster":
		if m.Scope.ClusterID == "" {
			return errors.New("scm: a Cluster-scoped object mapping needs a cluster id")
		}
		return nil
	case "ClusterGroup":
		if m.Scope.GroupID == "" {
			return errors.New("scm: a ClusterGroup-scoped object mapping needs a cluster group id")
		}
		return nil
	default:
		return fmt.Errorf("scm: an object mapping's scope has unrecognised type %q", m.Scope.Type)
	}
}

// MatchesRelease reports whether m is the release-name form and names
// exactly this Helm release. False for a label-selector-form entry, and
// false whenever releaseName or namespace is empty — a caller with no
// release identity to check (a plain kubectl-applied object, which has no
// Helm release at all) must not accidentally match a mapping with an empty
// ReleaseName/Namespace of its own.
func (m ObjectMapping) MatchesRelease(releaseName, namespace string) bool {
	return m.ReleaseName != "" && m.Namespace != "" &&
		releaseName != "" && namespace != "" &&
		m.ReleaseName == releaseName && m.Namespace == namespace
}

// MatchesLabels reports whether m is the label-selector form and every
// key/value pair it names is present, with an equal value, in labels — a
// SUBSET match, deliberately: an operator's selector identifies the object,
// it does not have to enumerate every label the object happens to carry.
// False for a release-form entry (empty LabelSelector never matches).
func (m ObjectMapping) MatchesLabels(labels map[string]string) bool {
	if len(m.LabelSelector) == 0 {
		return false
	}
	for k, v := range m.LabelSelector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// bindingSpec is the JSON shape SaveBinding writes into repository_bindings.spec
// — DESIGN.md §11.3's RepositoryBinding. Only the fields this package acts on are
// declared: the column is the contract of that section, so decoding it into a
// struct that claimed to be exhaustive would go stale the moment §11.3 grows a
// field.
type bindingSpec struct {
	FixBranch struct {
		Pattern string `json:"pattern"`
	} `json:"fixBranch"`
	PullRequest struct {
		// Pointer so "absent" and "false" are distinguishable — see
		// Binding.PullRequestEnabled for why they must not be conflated.
		Enabled *bool `json:"enabled"`
	} `json:"pullRequest"`
	WriteScope struct {
		ForbiddenPaths []string `json:"forbiddenPaths"`
	} `json:"writeScope"`
	// ObjectMappings is BACKLOG.md F19 mechanism 1 (2026-08-25) — see
	// ObjectMapping's own doc comment for the shape and DESIGN.md §11.1's
	// `clusterMappings` for the object-level sibling this is modelled on.
	// Absent (nil) on every binding registered before this field existed,
	// which decodes to an empty slice — exactly "no operator mapping
	// configured," the same honest default FindObjectMapping's "no match"
	// path already treats as normal.
	ObjectMappings []ObjectMapping `json:"objectMappings"`
}

// applySpec fills the spec-derived fields of b. A spec that does not parse is
// NOT fatal for the forbidden-path list, because ForbiddenPath enforces
// builtinForbiddenPaths regardless of what the binding says — so an unreadable
// spec degrades to "the non-overridable denylist only", never to "no denylist".
// It does disable pull requests, which is the safe direction: a binding whose
// stored policy cannot be read is a binding whose policy is unknown.
func applySpec(b *Binding, raw []byte) error {
	// A binding row written before spec existed, or with SQL NULL.
	if len(raw) == 0 {
		b.PullRequestEnabled = true
		return nil
	}
	var spec bindingSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("scm: binding %s has a spec that is not valid JSON, so its write policy cannot be read: %w", b.ID, err)
	}
	b.FixBranchPattern = spec.FixBranch.Pattern
	b.WriteScope.ForbiddenPaths = spec.WriteScope.ForbiddenPaths
	b.PullRequestEnabled = spec.PullRequest.Enabled == nil || *spec.PullRequest.Enabled
	b.ObjectMappings = spec.ObjectMappings
	return nil
}

// ErrNoBinding means no repository binding covers that URL. Distinct from
// ErrNotFound (which is about the provider's own 404s) because the remedy is
// completely different: register the repository, rather than look somewhere else
// in it.
var ErrNoBinding = errors.New("scm: no repository binding is registered for this repository")

// ErrRepoKeyConflict means an edited URL resolves to the same (tenant,
// repo_key) as a DIFFERENT existing binding. Two credentials for one physical
// repository is exactly what SaveBinding's own unique index forbids at
// create time; UpdateBinding must not be a backdoor around that guarantee.
var ErrRepoKeyConflict = errors.New("scm: another binding is already registered for that repository")

// Store persists bindings and their encrypted credentials.
//
// It takes a pgx.Tx rather than a pool so every call joins the caller's
// transaction and its RLS scope — the same convention internal/api's handlers
// use. A store that opened its own connection would silently escape row-level
// security, which is the one mistake this codebase's data layer is shaped to
// prevent.
type Store struct {
	keeper *secretbox.Keeper
}

func NewStore(keeper *secretbox.Keeper) *Store { return &Store{keeper: keeper} }

// SaveBinding registers a repository and seals its token.
//
// The token is sealed and the plaintext is zeroed before returning, per
// DESIGN.md §18.6's "in memory: zeroed after use" — which secretbox cannot do
// for the caller because it does not know when the caller is done.
func (s *Store) SaveBinding(ctx context.Context, tx pgx.Tx, tenantID string, in Binding, token []byte) (Binding, error) {
	defer secretbox.Zero(token)

	if len(token) == 0 {
		return Binding{}, errors.New("scm: a repository binding needs a token — an empty one would store a credential that cannot authenticate and fail only at PR time")
	}
	// Registration stays https-only (ParseRepoURL), deliberately, even though
	// matching now tolerates ssh: the operator is typing this once, through an
	// authenticated repo:write route, and a refusal here can name the https form
	// to use. Loosening the one rule that keeps a `file://` out of a stored
	// binding would buy a single paste's convenience.
	repo, host, err := ParseRepoURL(in.URL)
	if err != nil {
		return Binding{}, err
	}
	in.Host = host
	// The identity this binding will be FOUND by. Derived from the URL rather
	// than asked for, so it cannot disagree with it.
	repoKey := RepoKey(host, repo)

	if err := checkProviderImplemented(in.Provider); err != nil {
		return Binding{}, err
	}

	// BACKLOG.md F19 mechanism 1: validate every object mapping BEFORE any
	// write, same reasoning as ParseRepoURL above — a malformed entry must
	// refuse registration outright rather than get stored and silently never
	// match anything (or, worse, be ambiguous about which repo/path it means).
	for i, m := range in.ObjectMappings {
		if err := m.Validate(); err != nil {
			return Binding{}, fmt.Errorf("scm: object mapping %d: %w", i, err)
		}
	}

	// The credential this registration supersedes, if any. Read BEFORE the
	// upsert, because the upsert overwrites credential_ref and the old value is
	// unrecoverable afterwards.
	//
	// Without this, every token rotation left its predecessor in
	// encrypted_secrets forever: referenced by nothing, invisible to the API and
	// the UI, undeletable except by hand, and present in every backup taken
	// since. Rotating a token is the ordinary maintenance action on this feature
	// — a fine-grained token expires, so it happens on a schedule — so the leak
	// grows with normal use rather than only on a mistake.
	var supersededCredentialRef *string
	if err := tx.QueryRow(ctx,
		`SELECT credential_ref FROM repository_bindings WHERE tenant_id = $1 AND repo_key = $2`,
		tenantID, repoKey).Scan(&supersededCredentialRef); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, fmt.Errorf("scm: look up the credential being replaced: %w", err)
	}

	ciphertext, keyVersion, err := s.keeper.Seal(token)
	if err != nil {
		return Binding{}, fmt.Errorf("scm: seal credential: %w", err)
	}

	secretID := domain.NewID(domain.PrefixEncryptedSecret)
	if _, err := tx.Exec(ctx,
		`INSERT INTO encrypted_secrets (id, tenant_id, purpose, ciphertext, key_version, expires_at)
		 VALUES ($1, $2, 'scm_token', $3, $4, $5)`,
		secretID, tenantID, ciphertext, keyVersion, in.CredentialExpiresAt); err != nil {
		return Binding{}, fmt.Errorf("scm: store credential: %w", err)
	}

	// objectMappings defaults to an empty array rather than nil/null in the
	// stored JSON — cosmetic, but "no mappings configured" reading as `[]`
	// rather than `null` matches how every other slice-shaped part of this
	// spec (forbiddenPaths) is written.
	objectMappings := in.ObjectMappings
	if objectMappings == nil {
		objectMappings = []ObjectMapping{}
	}

	// spec holds DESIGN.md §11.3's RepositoryBinding shape, extended by
	// BACKLOG.md F19 (2026-08-25) with objectMappings — see ObjectMapping's
	// doc comment. Written as JSON rather than more columns because it is a
	// contract owned by that section, and columns would have to change every
	// time it does.
	spec, err := json.Marshal(map[string]any{
		"fixBranch":   map[string]any{"strategy": "newBranch", "pattern": "argus/fix-{incidentId}"},
		"pullRequest": map[string]any{"enabled": true},
		// §18.6's forbiddenPaths. Encrypted files and CI definitions are
		// excluded by default: ARGUS must not touch content it cannot read, and
		// must not be able to edit the pipeline that gates its own merge.
		"writeScope": map[string]any{"forbiddenPaths": []string{
			".github/workflows/**", ".gitlab-ci.yml", "**/*.sops.yaml", "**/*.enc.yaml", "**/sealed-secret*.yaml",
		}},
		"objectMappings": objectMappings,
	})
	if err != nil {
		return Binding{}, fmt.Errorf("scm: marshal binding spec: %w", err)
	}

	id := domain.NewID(domain.PrefixRepositoryBinding)
	row := tx.QueryRow(ctx,
		// ON CONFLICT keys on repo_key, not url — which is what makes token
		// rotation work when the operator retypes the same repository in a
		// different but equivalent form (a `.git` they added or dropped). Under
		// the old url-keyed conflict that produced a SECOND binding with a
		// second credential for one repository, and then which token got used
		// depended on the spelling the GitOps controller happened to report.
		// `url` is updated too, so the displayed URL is the one most recently
		// registered rather than a stale equivalent.
		//
		// spec is now in the DO UPDATE SET list — it previously was not, so a
		// re-registration (e.g. rotating a token) left whatever spec the FIRST
		// registration wrote untouched forever, because nothing before F19
		// (2026-08-25) ever gave an operator a way to change it anyway. F19
		// needs re-registering the same URL with new objectMappings to actually
		// apply the change ("supplying it updates it," matching how the
		// credential itself is rotated by re-registering) — every other spec
		// field is rebuilt from the same hardcoded defaults it always was, so
		// this is not a behavior change for fixBranch/pullRequest/writeScope
		// today, only the first field an operator can actually set.
		`INSERT INTO repository_bindings
		   (id, tenant_id, provider, url, repo_key, credential_ref, spec, api_base_url, host, default_branch)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, repo_key) DO UPDATE SET
		   provider = EXCLUDED.provider,
		   url = EXCLUDED.url,
		   credential_ref = EXCLUDED.credential_ref,
		   spec = EXCLUDED.spec,
		   api_base_url = EXCLUDED.api_base_url,
		   host = EXCLUDED.host,
		   default_branch = EXCLUDED.default_branch,
		   updated_at = now()
		 RETURNING id, created_at`,
		id, tenantID, in.Provider, in.URL, repoKey, secretID, spec,
		nullIfEmpty(in.APIBaseURL), in.Host, nullIfEmpty(in.DefaultBranch))
	if err := row.Scan(&in.ID, &in.CreatedAt); err != nil {
		return Binding{}, fmt.Errorf("scm: store binding: %w", err)
	}

	// Same transaction as the upsert that stopped referencing it, so there is no
	// window where the old row is unreferenced but still present. Guarded on
	// being genuinely different: re-registering with an identical token still
	// produces a new secret id, but a caller could in principle pass one back.
	if supersededCredentialRef != nil && *supersededCredentialRef != secretID {
		if _, err := tx.Exec(ctx, `DELETE FROM encrypted_secrets WHERE id = $1`, *supersededCredentialRef); err != nil {
			return Binding{}, fmt.Errorf("scm: delete the credential this registration replaced: %w", err)
		}
	}

	in.CredentialRef = secretID
	return in, nil
}

// BindingPatch is UpdateBinding's partial-update contract: a nil field means
// "leave this alone," the same pointer convention settings.UpdateProvider
// already uses for its own optional-secret problem (an admin renaming a
// provider shouldn't have to re-paste its API key). Every non-nil field,
// including an empty string, is APPLIED — that is how APIBaseURL/
// DefaultBranch get cleared, the same "blank means default" contract
// SaveBinding already gives the create path.
type BindingPatch struct {
	// A different URL changes repo_key, which is what UpdateBinding checks
	// for a conflict against every OTHER binding before applying.
	URL *string
	// "" clears it (public API) — same contract as create.
	APIBaseURL *string
	// "" clears it (auto-detect at PR time) — same contract as create.
	DefaultBranch *string
	// ExpiresAtProvided distinguishes "the operator did not touch this
	// field" from "the operator explicitly cleared the expiry": both leave
	// CredentialExpiresAt nil, so the pointer alone cannot tell them apart.
	ExpiresAtProvided   bool
	CredentialExpiresAt *time.Time
	// nil = unchanged. A non-nil slice, including an empty one, REPLACES the
	// stored list — the same "supplying it updates it" contract SaveBinding's
	// own doc comment already establishes for this field.
	ObjectMappings *[]ObjectMapping
}

// UpdateBinding changes an existing binding's fields by id, closing the gap
// SaveBinding's upsert-by-repo_key contract leaves: rotating a token already
// worked, by re-registering the same URL — but changing anything ELSE meant
// resending every field, since that path is a full overwrite (a default-branch
// correction that didn't happen to resend apiBaseUrl/objectMappings would
// silently wipe them back to their create-time defaults), and there was no
// way to fix the URL itself at all — a different URL is a different
// repo_key, so SaveBinding would register it as a brand new binding and leave
// the old one, and its credential, orphaned.
//
// token is optional: nil or empty leaves the stored credential untouched,
// matching settings.UpdateProvider's own "no value means don't touch it"
// contract. A non-empty token rotates it exactly like SaveBinding's own
// rotation path — seal a new encrypted_secrets row, point credential_ref at
// it, delete the superseded one in the same transaction. Provider is
// deliberately not in BindingPatch at all: changing it changes what the
// stored token can even authenticate as, which is a big enough change to ask
// for through delete-and-re-register rather than a field on an edit form.
func (s *Store) UpdateBinding(ctx context.Context, tx pgx.Tx, tenantID, id string, patch BindingPatch, token []byte) (Binding, error) {
	defer secretbox.Zero(token)

	var cur Binding
	var repoKey string
	var spec []byte
	// Joined to encrypted_secrets for its expires_at — same join ListBindings
	// already uses — so the untouched-expiry case below has the real current
	// value to echo back, not a zero value that would misreport this binding
	// as having no expiry when it does.
	if err := tx.QueryRow(ctx,
		`SELECT b.provider, b.url, b.repo_key, COALESCE(b.host, ''), COALESCE(b.api_base_url, ''),
		        COALESCE(b.default_branch, ''), b.credential_ref, b.spec, b.created_at, s.expires_at
		   FROM repository_bindings b
		   LEFT JOIN encrypted_secrets s ON s.id = b.credential_ref
		  WHERE b.id = $1`, id,
	).Scan(&cur.Provider, &cur.URL, &repoKey, &cur.Host, &cur.APIBaseURL,
		&cur.DefaultBranch, &cur.CredentialRef, &spec, &cur.CreatedAt, &cur.CredentialExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, ErrNoBinding
		}
		return Binding{}, fmt.Errorf("scm: look up binding to update: %w", err)
	}
	cur.ID = id

	newURL, newHost, newRepoKey := cur.URL, cur.Host, repoKey
	if patch.URL != nil && *patch.URL != cur.URL {
		repo, host, err := ParseRepoURL(*patch.URL)
		if err != nil {
			return Binding{}, err
		}
		newURL, newHost = *patch.URL, host
		newRepoKey = RepoKey(host, repo)

		var conflictingID string
		err = tx.QueryRow(ctx,
			`SELECT id FROM repository_bindings WHERE tenant_id = $1 AND repo_key = $2 AND id <> $3`,
			tenantID, newRepoKey, id).Scan(&conflictingID)
		if err == nil {
			return Binding{}, ErrRepoKeyConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, fmt.Errorf("scm: check for a repo_key conflict: %w", err)
		}
	}

	newAPIBaseURL := cur.APIBaseURL
	if patch.APIBaseURL != nil {
		newAPIBaseURL = *patch.APIBaseURL
	}
	newDefaultBranch := cur.DefaultBranch
	if patch.DefaultBranch != nil {
		newDefaultBranch = *patch.DefaultBranch
	}

	credentialRef := cur.CredentialRef
	rotated := len(token) > 0
	var supersededCredentialRef string
	if rotated {
		ciphertext, keyVersion, err := s.keeper.Seal(token)
		if err != nil {
			return Binding{}, fmt.Errorf("scm: seal credential: %w", err)
		}
		// Rotating without restating an expiry carries the OLD one forward
		// (cur.CredentialExpiresAt, already read above via the join) rather
		// than dropping it — a new token silently losing its expiry warning
		// would be worse than keeping a possibly-stale date, and the operator
		// can always clear it explicitly via ExpiresAtProvided.
		expiresAt := cur.CredentialExpiresAt
		if patch.ExpiresAtProvided {
			expiresAt = patch.CredentialExpiresAt
		}
		secretID := domain.NewID(domain.PrefixEncryptedSecret)
		if _, err := tx.Exec(ctx,
			`INSERT INTO encrypted_secrets (id, tenant_id, purpose, ciphertext, key_version, expires_at)
			 VALUES ($1, $2, 'scm_token', $3, $4, $5)`,
			secretID, tenantID, ciphertext, keyVersion, expiresAt); err != nil {
			return Binding{}, fmt.Errorf("scm: store credential: %w", err)
		}
		supersededCredentialRef, credentialRef = cur.CredentialRef, secretID
		cur.CredentialExpiresAt = expiresAt
	} else if patch.ExpiresAtProvided {
		// Not rotating, but the operator changed (or cleared) the expiry on
		// the credential already stored — update it in place rather than
		// touching the ciphertext.
		if _, err := tx.Exec(ctx, `UPDATE encrypted_secrets SET expires_at = $1 WHERE id = $2`,
			patch.CredentialExpiresAt, cur.CredentialRef); err != nil {
			return Binding{}, fmt.Errorf("scm: update credential expiry: %w", err)
		}
		cur.CredentialExpiresAt = patch.CredentialExpiresAt
	}

	// spec is only rewritten when objectMappings is actually part of this
	// patch. Every other write to it — fixBranch/pullRequest/writeScope — is
	// echoed back as read, unlike SaveBinding's full overwrite: a partial
	// update that silently reset the write policy back to hardcoded defaults
	// would be the same footgun this whole method exists to close for the
	// other fields.
	if patch.ObjectMappings != nil {
		for i, m := range *patch.ObjectMappings {
			if err := m.Validate(); err != nil {
				return Binding{}, fmt.Errorf("scm: object mapping %d: %w", i, err)
			}
		}
		objectMappings := *patch.ObjectMappings
		if objectMappings == nil {
			objectMappings = []ObjectMapping{}
		}
		newSpec, err := json.Marshal(map[string]any{
			"fixBranch":   map[string]any{"strategy": "newBranch", "pattern": "argus/fix-{incidentId}"},
			"pullRequest": map[string]any{"enabled": true},
			"writeScope": map[string]any{"forbiddenPaths": []string{
				".github/workflows/**", ".gitlab-ci.yml", "**/*.sops.yaml", "**/*.enc.yaml", "**/sealed-secret*.yaml",
			}},
			"objectMappings": objectMappings,
		})
		if err != nil {
			return Binding{}, fmt.Errorf("scm: marshal binding spec: %w", err)
		}
		spec = newSpec
	}

	tag, err := tx.Exec(ctx,
		`UPDATE repository_bindings SET
		   url = $1, repo_key = $2, host = $3, api_base_url = $4, default_branch = $5,
		   credential_ref = $6, spec = $7, updated_at = now()
		 WHERE id = $8`,
		newURL, newRepoKey, newHost, nullIfEmpty(newAPIBaseURL), nullIfEmpty(newDefaultBranch),
		credentialRef, spec, id)
	if err != nil {
		return Binding{}, fmt.Errorf("scm: update binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Binding{}, ErrNoBinding
	}

	// Same transaction as the update that stopped referencing it, so there is
	// no window where the old row is unreferenced but still present — same
	// reasoning as SaveBinding's own rotation cleanup.
	if rotated {
		if _, err := tx.Exec(ctx, `DELETE FROM encrypted_secrets WHERE id = $1`, supersededCredentialRef); err != nil {
			return Binding{}, fmt.Errorf("scm: delete the credential this update replaced: %w", err)
		}
	}

	cur.URL, cur.Host, cur.APIBaseURL, cur.DefaultBranch, cur.CredentialRef = newURL, newHost, newAPIBaseURL, newDefaultBranch, credentialRef
	// spec here is exactly what was just persisted — freshly marshaled above
	// when ObjectMappings was part of this patch, or the original bytes read
	// at the top of this function otherwise — so this is the one accurate
	// source for the response's ObjectMappings, matching ListBindings' own
	// use of applySpec rather than hand-copying one field.
	if err := applySpec(&cur, spec); err != nil {
		logger.ErrorContext(ctx, "updating a repository binding failed", logging.Err(err))
	}
	return cur, nil
}

// ListBindings returns every binding, never the credentials. Deliberately: this
// feeds an API response, and a list endpoint that could return a token is one
// refactor away from doing so.
//
// ObjectMappings IS populated here (via applySpec, the same decode ProviderFor
// uses) — unlike WriteScope/FixBranchPattern, which stay zero because nothing
// in a list response needs the write policy. A list is also the ONE read this
// package has that an editing UI can pre-fill from, and an edit form that
// cannot show what mappings already exist would only ever be able to
// overwrite them blind — the exact hazard BindingPatch.ObjectMappings' own
// "supplying it replaces the list" contract was written to warn against.
func (s *Store) ListBindings(ctx context.Context, tx pgx.Tx) ([]Binding, error) {
	rows, err := tx.Query(ctx,
		`SELECT b.id, b.provider, b.url, COALESCE(b.host, ''), COALESCE(b.api_base_url, ''),
		        COALESCE(b.default_branch, ''), b.credential_ref, b.spec, s.expires_at, b.created_at
		   FROM repository_bindings b
		   LEFT JOIN encrypted_secrets s ON s.id = b.credential_ref
		  ORDER BY b.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("scm: list bindings: %w", err)
	}
	defer rows.Close()

	out := []Binding{}
	for rows.Next() {
		var b Binding
		var spec []byte
		if err := rows.Scan(&b.ID, &b.Provider, &b.URL, &b.Host, &b.APIBaseURL,
			&b.DefaultBranch, &b.CredentialRef, &spec, &b.CredentialExpiresAt, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scm: scan binding: %w", err)
		}
		// applySpec also fills WriteScope/FixBranchPattern/PullRequestEnabled,
		// none of which this response actually uses — harmless, since nothing
		// here forwards them anywhere, and simpler than a second, narrower
		// decode that only extracts ObjectMappings. An unparsable spec is not
		// fatal for a list, same as applySpec's own doc comment already
		// established for ProviderFor: the mappings just read back empty
		// rather than failing the whole list.
		if err := applySpec(&b, spec); err != nil {
			logger.ErrorContext(ctx, "scanning a repository binding failed", logging.Err(err))
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBinding removes a binding and its credential together.
//
// Both or neither: a binding without its secret is unusable, and a secret
// without its binding is an orphaned credential nobody can see or revoke —
// which is strictly worse than either.
func (s *Store) DeleteBinding(ctx context.Context, tx pgx.Tx, id string) error {
	var credentialRef string
	err := tx.QueryRow(ctx,
		`DELETE FROM repository_bindings WHERE id = $1 RETURNING credential_ref`, id).Scan(&credentialRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoBinding
	}
	if err != nil {
		return fmt.Errorf("scm: delete binding: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM encrypted_secrets WHERE id = $1`, credentialRef); err != nil {
		return fmt.Errorf("scm: delete binding credential: %w", err)
	}
	return nil
}

// ProviderFor resolves a repository URL to a ready-to-use Provider.
//
// This is the function the PR path calls, and it is where the host check lives.
// The URL arrives from a cluster object, so matching it against the REGISTERED
// binding's host is what stops a tenant-influenced `spec.source.repoURL` from
// pointing ARGUS's credential at a host the operator never approved.
//
// The caller must not retain the returned Provider beyond the operation: it
// holds the decrypted token.
func (s *Store) ProviderFor(ctx context.Context, tx pgx.Tx, repoURL string) (Provider, Repo, Binding, error) {
	// ParseRepoRef, not ParseRepoURL: this URL came from a cluster object and is
	// used only to RECOGNISE the repository, never to dial it. See ParseRepoRef
	// for why an ssh remote must still resolve to the https binding an operator
	// registered — Argo CD installations commonly sync over ssh, and refusing
	// that would leave the pull-request path unreachable while telling the
	// operator to register a repository they already had.
	repo, host, err := ParseRepoRef(repoURL)
	if err != nil {
		return nil, Repo{}, Binding{}, err
	}
	repoKey := RepoKey(host, repo)

	var b Binding
	var ciphertext, keyVersion string
	// spec comes back with the credential in one round trip: the write path needs
	// the binding's forbiddenPaths at the same moment it needs the token, and
	// fetching the policy separately would create a window where one could be
	// read without the other.
	var specRaw []byte
	err = tx.QueryRow(ctx,
		`SELECT b.id, b.provider, b.url, COALESCE(b.host, ''), COALESCE(b.api_base_url, ''),
		        COALESCE(b.default_branch, ''), b.credential_ref, b.spec, s.ciphertext, s.key_version, s.expires_at
		   FROM repository_bindings b
		   JOIN encrypted_secrets s ON s.id = b.credential_ref
		  WHERE b.repo_key = $1`, repoKey).Scan(
		&b.ID, &b.Provider, &b.URL, &b.Host, &b.APIBaseURL, &b.DefaultBranch,
		&b.CredentialRef, &specRaw, &ciphertext, &keyVersion, &b.CredentialExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// The honest degradation DESIGN.md §11.2 step 6 asks for: say so, and
		// say what would fix it, rather than failing obscurely.
		// Names the identity it looked for, not just the URL it was given. The
		// two differ exactly when the controller's URL form differs from the
		// registered one, which is precisely the case where "register it" would
		// otherwise be the wrong advice.
		return nil, Repo{}, Binding{}, fmt.Errorf("%w: %s (looked for %s). Register it in Settings with a token that may write to it, and ARGUS can propose the fix as a pull request instead of an in-place change", ErrNoBinding, repoURL, repoKey)
	}
	if err != nil {
		return nil, Repo{}, Binding{}, fmt.Errorf("scm: look up binding: %w", err)
	}

	// Redundant by construction now — repo_key begins with the normalised host,
	// so a key match already proves the hosts agree — and kept anyway as an
	// assertion. If RepoKey ever changes shape in a way that drops or weakens
	// the host component, this is what fails instead of a credential being sent
	// to a host nobody registered. Compared on normalised hostnames so a stored
	// host carrying a port cannot make a genuine match look like a mismatch.
	if b.Host != "" && !MatchesHost(host, normalizeHost(b.Host)) {
		return nil, Repo{}, Binding{}, fmt.Errorf("scm: repository URL host %q does not match the registered binding's host %q — refusing to use that binding's credential against a different host", host, b.Host)
	}

	// Before the token is decrypted: a binding whose write policy cannot be read
	// must not hand out a usable credential.
	if err := applySpec(&b, specRaw); err != nil {
		return nil, Repo{}, Binding{}, err
	}

	token, err := s.keeper.Open(ciphertext, keyVersion)
	if err != nil {
		return nil, Repo{}, Binding{}, fmt.Errorf("scm: could not decrypt the stored credential for %s: %w", repoURL, err)
	}

	// Re-checked here as well as at registration, because a binding row can
	// predate a provider being removed and because this is the last point before
	// a decrypted token would be handed to a client.
	if err := checkProviderImplemented(b.Provider); err != nil {
		secretbox.Zero(token)
		return nil, Repo{}, Binding{}, err
	}

	// The operator's allowlist of private destinations this provider's client
	// may reach (migration 000115) — a self-hosted GHES or GitLab CE/EE on an
	// internal address is a real deployment, and naming it here is the only
	// way past internal/outbound's default-deny.
	//
	// READ EAGERLY HERE, not lazily at dial time, and the reason is a live
	// caller rather than a preference: internal/api/mergecheck.go commits tx
	// BEFORE it calls the provider ("everything past here is a network call,
	// so it runs outside the transaction above"), and several other callers
	// could reasonably do the same. A closure that read settings through tx at
	// dial time would find a finished transaction in exactly those cases and
	// refuse a destination the operator had legitimately allowlisted — a
	// setting that works on some routes and silently not on others, which is
	// worse than one that does not exist.
	//
	// The error is captured rather than returned: a settings read that failed
	// must not take down a pull-request operation against a PUBLIC host that
	// never needed the allowlist at all. internal/outbound calls this only
	// when it is about to refuse a private address, and turns the error into a
	// refusal that names the read failure — so the failure stays scoped to the
	// destinations it actually decides.
	allowedPrivate, allowedPrivateErr := resolvePrivateDestinations(ctx, tx)
	privateDestinations := func(context.Context) (outbound.Allowlist, error) {
		return allowedPrivate, allowedPrivateErr
	}

	switch b.Provider {
	case "github":
		// The token is copied into the provider as a string, so the caller's
		// byte slice can be zeroed immediately. Go strings are immutable and
		// cannot be zeroed, which is an accepted limit of this design and the
		// reason the provider must be short-lived.
		p := &GitHub{BaseURL: b.APIBaseURL, Token: string(token), UserAgent: "argus", PrivateDestinations: privateDestinations}
		secretbox.Zero(token)
		return p, repo, b, nil
	case "gitlab":
		p := &GitLab{BaseURL: b.APIBaseURL, Token: string(token), UserAgent: "argus", PrivateDestinations: privateDestinations}
		secretbox.Zero(token)
		return p, repo, b, nil
	default:
		// Unreachable while checkProviderImplemented and this switch agree, which
		// is what implementedProviders exists to guarantee. Kept so that adding a
		// name to that map without adding a case here fails loudly rather than
		// returning a nil provider.
		secretbox.Zero(token)
		return nil, Repo{}, Binding{}, fmt.Errorf("scm: provider %q is listed as implemented but has no constructor — this is a bug in this package, not a configuration problem", b.Provider)
	}
}

// resolvePrivateDestinations reads and validates the operator allowlist for a
// repository client. Split out of ProviderFor so the "read it while the
// transaction is definitely open" decision has one place to be read and
// changed — see its call site for why that timing is load-bearing.
func resolvePrivateDestinations(ctx context.Context, tx pgx.Tx) (outbound.Allowlist, error) {
	cfg, err := settings.Resolve(ctx, tx)
	if err != nil {
		return outbound.Allowlist{}, fmt.Errorf("scm: read the outbound private-destination allowlist: %w", err)
	}
	return cfg.PrivateDestinationAllowlist()
}

// implementedProviders is the single source of truth for which Git hosts this
// build can actually talk to.
//
// It exists because the two answers had drifted apart in a way that mattered:
// SaveBinding accepted "gitlab" (it is a first-class provider in the design, and
// the Provider interface is shaped for it — D-R6) while ProviderFor refused it,
// so registering a GitLab repository returned 201 Created with
// credentialStored: true and sealed a token that could never be used for
// anything. A stored secret with no possible use is pure exposure: it is at rest
// in the database, it is in every backup, and the only thing it can do is fail
// later, further from the mistake that created it.
//
// Named for what it means rather than "valid providers", because the design's
// list and this build's list are genuinely different things and conflating them
// is how the drift happened.
//
// BACKLOG.md F15 closed the gap this map exists to describe: GitLab now has a
// real implementation (gitlab.go) and is listed here alongside GitHub.
var implementedProviders = map[string]bool{"github": true, "gitlab": true}

// designedProviders is what the shape supports but this build does not, kept
// separate so the refusal can say "not yet" rather than "unknown", which is the
// difference between a roadmap item and a typo. Empty now that GitHub and
// GitLab — the two providers D-R6 named — are both implemented; kept as a map
// rather than deleted so the NEXT provider this design grows has an obvious
// place to be listed as "designed but not yet built" before anyone codes it.
var designedProviders = map[string]string{}

func checkProviderImplemented(provider string) error {
	if implementedProviders[provider] {
		return nil
	}
	if why, designed := designedProviders[provider]; designed {
		return fmt.Errorf("scm: provider %q cannot be used yet: %s. Registering it would store a credential that can never authenticate anything, so it is refused here rather than at the first pull request", provider, why)
	}
	return fmt.Errorf("scm: provider must be %q or %q, got %q", "github", "gitlab", provider)
}

// ExpiringCredentials lists bindings whose token expires within d.
//
// The whole reason the expiry is stored. D-R9: "store the expiry and warn
// BEFORE it, not report the resulting PR failures after" — reporting "PR
// creation failed" on the day a token dies is exactly the silent degradation
// this product exists to remove.
func (s *Store) ExpiringCredentials(ctx context.Context, tx pgx.Tx, within time.Duration) ([]Binding, error) {
	rows, err := tx.Query(ctx,
		`SELECT b.id, b.provider, b.url, s.expires_at
		   FROM repository_bindings b
		   JOIN encrypted_secrets s ON s.id = b.credential_ref
		  WHERE s.expires_at IS NOT NULL AND s.expires_at <= now() + $1::interval
		  ORDER BY s.expires_at`, fmt.Sprintf("%d seconds", int(within.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("scm: list expiring credentials: %w", err)
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		var b Binding
		if err := rows.Scan(&b.ID, &b.Provider, &b.URL, &b.CredentialExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// MatchedObjectMapping is what FindObjectMapping returns on success: the
// registered Binding a match was found on, and the one ObjectMapping entry
// that matched. Binding.ObjectMappings is left zero here, deliberately —
// unlike ListBindings (which now does populate it, for an editing UI to
// pre-fill from): the caller here already has the single mapping that
// matched, and re-populating the whole list would invite iterating it a
// second time and silently diverging from what actually matched.
type MatchedObjectMapping struct {
	Binding Binding
	Mapping ObjectMapping
}

// FindObjectMapping is BACKLOG.md F19 mechanism 1's read side (F30-corrected
// for multi-cluster): given a candidate Helm release identity and/or a
// candidate set of labels, look for an operator-declared objectMappings
// entry, on ANY binding registered for this tenant, that names it AND whose
// Scope covers clusterID.
//
// Checked in this order, first match wins:
//
//  1. Release-name form — only attempted when releaseName AND
//     releaseNamespace are both non-empty (a plain kubectl-applied object has
//     no release at all, so this step is a no-op for it, exactly as F19's own
//     text expects).
//  2. Label-selector form — only attempted when labels is non-empty. The
//     only form that can match an object with no Helm release, and usable
//     for a Helm release too if an operator prefers a selector.
//
// clusterID is checked against each candidate mapping's own Scope via
// authz.ScopeIncludesCluster — this is F30's fix for the failure mode an
// unscoped match had: a mapping for "shop-apps in default" used to match that
// release/namespace on EVERY cluster in the fleet, so a dev/prod split fed
// from different overlays got one (wrong, for one of them) path for both. An
// identity match whose scope does not cover this cluster is skipped, not
// treated as a hit — the search continues to the next candidate exactly as
// if that mapping simply were not there for this cluster.
//
// A function, not a *Store method: unlike SaveBinding/ProviderFor this needs
// no credential decryption at all, only the tenant-scoped repository_bindings
// row and its spec — so it takes nothing this package's Store constructor
// would otherwise have to supply.
//
// Runs inside the caller's transaction, so it is scoped by whatever RLS scope
// that transaction already carries (internal/data.SetRequestScope) — a
// mapping registered under one tenant can never be read by a different
// tenant's transaction, the same guarantee every other query against this
// table has. This is not a special case this function adds; it is what
// happens when a query has no way to ask for a scope of its own.
//
// No match is a completely normal outcome — an operator simply has not
// configured one — and returns found=false, err=nil, matching this feature's
// own "give up honestly" framing (DESIGN.md §11.2 step 6). Only a genuine
// read failure (a broken connection, a spec so malformed even individual
// bindings cannot be skipped past) returns a non-nil error.
func FindObjectMapping(ctx context.Context, tx pgx.Tx, clusterID, releaseName, releaseNamespace string, labels map[string]string) (MatchedObjectMapping, bool, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, provider, url, COALESCE(host, ''), COALESCE(api_base_url, ''),
		        COALESCE(default_branch, ''), credential_ref, spec, created_at
		   FROM repository_bindings
		  ORDER BY created_at`)
	if err != nil {
		return MatchedObjectMapping{}, false, fmt.Errorf("scm: list bindings for object-mapping match: %w", err)
	}
	defer rows.Close()

	type candidate struct {
		binding Binding
		spec    bindingSpec
	}
	var candidates []candidate
	for rows.Next() {
		var b Binding
		var specRaw []byte
		if err := rows.Scan(&b.ID, &b.Provider, &b.URL, &b.Host, &b.APIBaseURL,
			&b.DefaultBranch, &b.CredentialRef, &specRaw, &b.CreatedAt); err != nil {
			return MatchedObjectMapping{}, false, fmt.Errorf("scm: scan binding for object-mapping match: %w", err)
		}
		var spec bindingSpec
		if len(specRaw) > 0 {
			if err := json.Unmarshal(specRaw, &spec); err != nil {
				// Same treatment applySpec gives an unreadable spec elsewhere in
				// this package: skip this ONE binding's mappings rather than fail
				// the whole search over one malformed row — a bad spec on binding
				// A must not stop binding B's mapping from being found.
				logger.WarnContext(ctx, "repository binding has a spec that is not valid JSON; skipping its object mappings",
					slog.String("binding_id", b.ID), logging.Err(err))
				continue
			}
		}
		candidates = append(candidates, candidate{binding: b, spec: spec})
	}
	if err := rows.Err(); err != nil {
		return MatchedObjectMapping{}, false, err
	}

	if releaseName != "" && releaseNamespace != "" {
		for _, c := range candidates {
			for _, m := range c.spec.ObjectMappings {
				if !m.MatchesRelease(releaseName, releaseNamespace) {
					continue
				}
				covers, err := authz.ScopeIncludesCluster(ctx, tx, m.Scope, clusterID)
				if err != nil {
					return MatchedObjectMapping{}, false, fmt.Errorf("scm: resolve scope for a matched release mapping on binding %s: %w", c.binding.ID, err)
				}
				if covers {
					return MatchedObjectMapping{Binding: c.binding, Mapping: m}, true, nil
				}
			}
		}
	}
	if len(labels) > 0 {
		for _, c := range candidates {
			for _, m := range c.spec.ObjectMappings {
				if !m.MatchesLabels(labels) {
					continue
				}
				covers, err := authz.ScopeIncludesCluster(ctx, tx, m.Scope, clusterID)
				if err != nil {
					return MatchedObjectMapping{}, false, fmt.Errorf("scm: resolve scope for a matched label mapping on binding %s: %w", c.binding.ID, err)
				}
				if covers {
					return MatchedObjectMapping{Binding: c.binding, Mapping: m}, true, nil
				}
			}
		}
	}
	return MatchedObjectMapping{}, false, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
