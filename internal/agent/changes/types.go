// Package changes turns object-cache updates into field-level change records
// for the "what changed before this broke?" feed (CI-S2).
//
// Every differ here is a pure function over two snapshots of one object. The
// object cache has already replaced every container env value and every
// ConfigMap data/binaryData value with "sha256:<hex>" before these functions
// see them, so the differs compare hashes and report that a key changed —
// never what it changed to. Secrets are not cached and have no differ.
package changes

import "time"

// Op values for ChangeEvent.Op.
const (
	OpAdd    = "add"
	OpUpdate = "update"
	OpDelete = "delete"
)

// MaxValueLen is the longest value string (in runes) a FieldChange or summary
// part carries; longer strings are cut and end in TruncationMarker.
const MaxValueLen = 256

// TruncationMarker ends every value string cut at MaxValueLen.
const TruncationMarker = "…"

// Words used as the only value of key-level changes (ConfigMap data keys,
// container env vars) — the old and new values are never emitted.
const (
	ValueAdded    = "added"
	ValueRemoved  = "removed"
	ValueModified = "modified"
)

// FieldChange is one tracked field that differs between two snapshots.
// OldValue/NewValue are nil when the field is absent on that side.
type FieldChange struct {
	Path     string `json:"path"`
	OldValue any    `json:"oldValue"`
	NewValue any    `json:"newValue"`
}

// DiffInfo is the set of tracked-field changes for one update plus a
// one-line human summary.
type DiffInfo struct {
	Fields  []FieldChange `json:"fields"`
	Summary string        `json:"summary"`
}

// ChangeEvent is one observed add, update or delete of a tracked object, the
// unit the agent batches to the hub.
type ChangeEvent struct {
	ObservedAt time.Time     `json:"observedAt"`
	Kind       string        `json:"kind"`
	APIGroup   string        `json:"apiGroup"`
	Namespace  string        `json:"namespace,omitempty"`
	Name       string        `json:"name"`
	UID        string        `json:"uid,omitempty"`
	OwnerKind  string        `json:"ownerKind,omitempty"`
	OwnerName  string        `json:"ownerName,omitempty"`
	Op         string        `json:"op"`
	Fields     []FieldChange `json:"fields,omitempty"`
	Summary    string        `json:"summary,omitempty"`
}

// Classify reports whether changes to objects of this kind and API group are
// recorded at all. Only kinds with an audited differ are tracked; Secrets
// and SealedSecrets never are, whatever group they claim.
func Classify(kind, apiGroup string) bool {
	if isSecretKind(kind) {
		return false
	}
	reg, ok := diffFunctions[kind]
	return ok && reg.group == apiGroup
}

func isSecretKind(kind string) bool {
	return kind == "Secret" || kind == "SealedSecret"
}
