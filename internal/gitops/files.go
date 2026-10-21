package gitops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"argus/internal/redact"
	"gopkg.in/yaml.v3"
)

// Whole-file edits: the ONE shape a repository change takes.
//
// # What replaced the single-field grammar, and why
//
// Until 2026-08-28 this package could express exactly one repository change:
// replace one scalar, in one file, that already existed, in a file containing
// no template markers — and prove, structurally, that nothing else moved
// (verifyOnlyFieldChanged). That proof worked. It was also the ceiling on what
// ARGUS could propose at all, and the ceiling sat far below the problem:
// most of the fault catalogue's repository-channel entries need a change that
// is not one scalar in one plain-YAML file — a Helm values key feeding a
// template, a Kustomize overlay patch, a probe block that has to be added, two
// files that have to move together.
//
// A narrow verification mechanism must not be the ceiling on a general
// capability. So the grammar is now: **one or more files, each with its whole
// proposed new content**. ARGUS computes the diff — it never asks a model for
// one — and the safety story is stated honestly rather than overstated:
//
//   - The real gate on a pull request is a human reading the diff and merging
//     it. Nothing ARGUS proposes reaches a cluster without that.
//   - Around it sit the boundaries that are NOT judgement calls and are
//     enforced here and in propose.go: the privilege-escalation denylist
//     (scm.ForbiddenPath), confinement to the registered source directory,
//     reads pinned to the synced commit, compare-and-swap on push, no
//     auto-merge, capability gates, and redaction on the way out of the
//     cluster.
//
// # What is still refused, and what is now only reported
//
// Refused (the edit does not become a pull request):
//
//   - Empty content, or content over the manifest byte bound.
//   - A path that is forbidden, outside the synced directory, or duplicated
//     within one proposal (propose.go).
//   - Content that introduces internal/redact's marker — BUGS.md 112. The
//     model is structurally never shown a redacted value, so writing the
//     marker back out as if it were content is always wrong.
//   - Unparseable YAML in a file that is plain YAML (see plainYAML below). A
//     manifest that does not parse is not a change a reviewer can review.
//
// Reported as an ADVISORY on the change, not refused:
//
//   - The file is templated ({{ }}) or is not YAML at all, so ARGUS did not
//     parse it. Refusing this was the single biggest cap on Helm coverage: a
//     templated file is editable, the model reads it, and the diff is what a
//     reviewer checks.
//   - The document count changed, or the file no longer declares the object
//     this incident is about. Both are legitimate whole-file edits (splitting
//     a manifest, editing a values file that declares no Kubernetes object at
//     all), and an assertion that is meaningless for a values.yaml must not be
//     a refusal for one.
//
// An advisory is not a shrug: every one of them is rendered in the preview an
// operator reads and in the pull-request body a reviewer reads, next to the
// diff it qualifies.

var (
	// ErrVerificationFailed is a proposed file failing one of the checks that
	// are still hard refusals above. It remains the most important error in
	// this package: it is what stops content that cannot be reviewed becoming
	// a pull request.
	ErrVerificationFailed = errors.New("gitops: refusing this edit")
	// ErrAmbiguousDocument means an object is defined more than once in a
	// file, or not at all. Refuse rather than guess — the rule LocateIn's doc
	// comment established after the same object turned up twice in Argo CD's
	// own example repository. Used by file DISCOVERY (which file does this
	// object live in), not by the edit itself.
	ErrAmbiguousDocument = errors.New("gitops: cannot tell which document in this file defines the object")
	// ErrRedactedValueEchoed means the proposed content carries redact.Marker
	// where the original did not — BUGS.md 112, whose live instance was a plan
	// proposing `RETRY_LIMIT: "[REDACTED]"` as a real ConfigMap value, approved
	// and shipped as a real pull request. internal/redact strips every
	// ConfigMap/Secret data value and every literal env value before the object
	// crosses the tunnel, so the model has no basis to know the real value and
	// the marker is never content.
	ErrRedactedValueEchoed = errors.New("gitops: this content carries the redaction marker used to hide secret material from the model — refusing to write it into a file as if it were real content")
	// ErrNothingToChange means every proposed file already holds exactly the
	// content being proposed for it. A pull request with no change in it is
	// not a proposal.
	ErrNothingToChange = errors.New("gitops: none of the proposed files differ from their content at the synced commit")
)

// FileEdit is one file's whole proposed content — a path plus the bytes the
// file should end up holding. Not a diff, not a patch, and not a field/value
// pair: ARGUS computes the diff from this against what the file holds at the
// pinned commit, so there is no diff format for anything upstream to get
// wrong.
//
// Delete is the exception to "content" being what this carries: it asks for
// the path to be REMOVED rather than written, and Content is ignored when it
// is set (see ApplyFileDelete). This is BACKLOG.md "still open" #2's fix — a
// deliberate, explicit field rather than reusing empty Content to mean
// delete, because empty content refusing outright (ApplyFileEdit, scm.PutFile,
// scm.PutFiles all refuse it) is itself load-bearing elsewhere: an OpenPR plan
// that accidentally clears a file's content must still be refused as
// malformed, not silently reinterpreted as an intentional deletion.
type FileEdit struct {
	// Path is relative to the repository root.
	Path string
	// Content is the file exactly as it should read after the change. Unused
	// when Delete is true.
	Content []byte
	// Delete asks for Path to be removed from the repository entirely,
	// instead of written with Content.
	Delete bool
}

// FileChange is one FileEdit after it has been read against the pinned commit,
// checked, and diffed.
type FileChange struct {
	Path string
	// Original is the file at the synced commit — empty when Created.
	Original []byte
	// Content is the proposed content, byte for byte as submitted.
	Content []byte
	// BlobSHA is the blob the edit was computed against and which the commit
	// uses as its compare-and-swap token. Empty exactly when Created.
	BlobSHA string
	// Created is true when the file does not exist at the synced commit.
	Created bool
	// Deleted is true when this change REMOVES Path rather than writing it —
	// ApplyFileDelete's result, never set alongside Created (a file must
	// already exist, and be read successfully, to be deleted at all — see
	// prepareChanges' ErrNotFound handling for a delete edit).
	Deleted bool
	// Unchanged is true when Content already equals Original. Such a file is
	// reported and NOT committed — a multi-file proposal where an operator
	// edited two of the three files they opened is a normal thing to submit,
	// and silently committing a no-op or refusing the whole proposal are both
	// worse answers than saying which files actually move. Always false for
	// a deletion: a file that exists is never "already deleted".
	Unchanged bool

	// Diff is a full multi-hunk unified diff of this file, computed by ARGUS.
	Diff         string
	LinesAdded   int
	LinesRemoved int
	LineCount    int
	// DocumentCount is how many YAML documents the proposed content holds, or
	// 0 when it was not parsed (see Advisories).
	DocumentCount int
	// Parsed says whether ARGUS parsed this file as YAML at all.
	Parsed bool

	// Checks is what ARGUS asserted about this file, in words, for the
	// pull-request body and the API response.
	Checks []string
	// Advisories are the things a reviewer must check because ARGUS cannot:
	// a templated file it did not parse, a changed document count, an object
	// identity that moved. Rendered alongside the diff everywhere it appears.
	Advisories []string
}

// ChangeVerification is what was proven about a whole proposal — one or many
// files. It exists to be quoted (pull-request body, audit record, API
// response), because the argument for trusting a machine-proposed change is
// that the claim is checkable by the human reading it, not that a badge says
// "verified".
type ChangeVerification struct {
	// Files is one entry per proposed file, in the order submitted, including
	// the unchanged ones.
	Files []FileChange
	// FilesChanged counts the entries that are actually being committed.
	FilesChanged int
	LinesAdded   int
	LinesRemoved int
	// Checks and Advisories are the aggregate of the per-file ones, prefixed
	// with the file they came from when there is more than one file.
	Checks     []string
	Advisories []string
}

// Changed returns only the files that actually differ — what propose.go
// commits, and what a caller should render.
func (v ChangeVerification) Changed() []FileChange {
	out := make([]FileChange, 0, len(v.Files))
	for _, f := range v.Files {
		if !f.Unchanged {
			out = append(out, f)
		}
	}
	return out
}

// Paths lists every file being committed, for a summary line.
func (v ChangeVerification) Paths() []string {
	out := make([]string, 0, v.FilesChanged)
	for _, f := range v.Changed() {
		out = append(out, f.Path)
	}
	return out
}

// ApplyFileEdit checks one proposed whole-file edit against the file as it is
// at the pinned commit and returns the diffed, checked result.
//
// original is empty (and created true) when the file does not exist at that
// commit. object is the Kubernetes object this incident is about, used ONLY
// for the advisory identity note — a values.yaml declares no Kubernetes object
// at all, so an identity assertion is a category error there, not a near miss.
func ApplyFileEdit(original []byte, edit FileEdit, created bool, object ObjectRef) (FileChange, error) {
	if len(bytes.TrimSpace(edit.Content)) == 0 {
		return FileChange{}, fmt.Errorf("%w: %s has no content — an empty file is almost never the intended change, and it is the shape a decode failure upstream would take", ErrVerificationFailed, edit.Path)
	}
	if len(edit.Content) > maxManifestBytes {
		return FileChange{}, fmt.Errorf("%w: the proposed content for %s is %d bytes, over the %d-byte bound", ErrVerificationFailed, edit.Path, len(edit.Content), maxManifestBytes)
	}
	// BUGS.md 112, applied to the new grammar: refuse content that INTRODUCES
	// the marker. Checked as an introduction rather than as presence so a file
	// that already carried the literal string at the synced commit — however
	// it got there — can still be edited elsewhere, while a model writing the
	// marker out as if it were a real value is refused.
	if bytes.Contains(edit.Content, []byte(redact.Marker)) && !bytes.Contains(original, []byte(redact.Marker)) {
		return FileChange{}, fmt.Errorf("%w: %s would gain %q, which is what internal/redact substitutes for a value that was withheld from the model at capture time — a human must supply the real value, not the marker that stood in for it",
			ErrRedactedValueEchoed, edit.Path, redact.Marker)
	}

	change := FileChange{
		Path:     edit.Path,
		Original: original,
		Content:  edit.Content,
		Created:  created,
	}
	if !created && bytes.Equal(normalizeTrailingNewline(original), normalizeTrailingNewline(edit.Content)) {
		// Reported, not refused — see FileChange.Unchanged.
		change.Unchanged = true
		change.Checks = []string{fmt.Sprintf("%s is unchanged from the synced commit and will not be committed", edit.Path)}
		return change, nil
	}

	beforeLines := strings.Split(string(original), "\n")
	if created {
		beforeLines = nil
	}
	afterLines := strings.Split(string(edit.Content), "\n")
	change.Diff, change.LinesAdded, change.LinesRemoved = freeformUnifiedDiff(beforeLines, afterLines)
	change.LineCount = len(afterLines)

	// The parse. plainYAML decides whether a parse failure is a refusal or an
	// expected property of the file: a chart template is not valid YAML and
	// never was, and refusing it for that is exactly the cap being removed.
	templated := looksTemplated(edit.Content) || (!created && looksTemplated(original))
	yamlExt := hasYAMLExtension(edit.Path)
	docs, perr := parseDocumentsStrict(edit.Content)
	if perr == nil && !templated {
		// DocumentCount is reported only when Parsed is true. A templated
		// file's YAML-ness is an accident (see the switch below), so reporting
		// a document count for one would be a number about the wrong artefact —
		// and a caller rendering "3 documents" next to "ARGUS did not parse
		// this file" is showing two statements that contradict each other.
		change.Parsed = true
		change.DocumentCount = len(docs)
	}
	switch {
	case templated:
		// The advisory is independent of whether the bytes happen to parse.
		// A chart template's YAML-ness is an accident — `name: {{ x }}` parses
		// as a nested flow mapping and means nothing — so a parse here would be
		// a claim about the wrong artefact. What ARGUS did NOT do is render it,
		// and that is what the reviewer needs told.
		change.Advisories = append(change.Advisories, fmt.Sprintf("%s is templated (it contains Go template markers), so ARGUS did not render it and makes no claim about what it renders to. The diff below is the whole of what is being proposed for this file — review it as you would a hand-written patch", edit.Path))
	case perr == nil:
		change.Checks = append(change.Checks, fmt.Sprintf("%s re-parses as valid YAML (%d document(s))", edit.Path, len(docs)))
	case !yamlExt:
		change.Advisories = append(change.Advisories, fmt.Sprintf("%s is not a YAML file, so ARGUS did not parse it. The diff is the whole of what is being claimed about it", edit.Path))
	default:
		// Plain YAML that does not parse: still a refusal. A manifest a
		// controller cannot apply is not a change a reviewer can review, and
		// nothing about whole-file editing makes that better.
		return FileChange{}, fmt.Errorf("%w: the proposed content for %s is plain YAML and does not parse, so it could not be applied: %v", ErrVerificationFailed, edit.Path, perr)
	}

	// Document count and object identity: advisory, both of them.
	if change.Parsed && !created {
		if before, berr := parseDocumentsStrict(original); berr == nil {
			if len(before) != len(docs) {
				change.Advisories = append(change.Advisories, fmt.Sprintf("%s held %d YAML document(s) at the synced commit and holds %d in this proposal — check that adding or removing a document is intended", edit.Path, len(before), len(docs)))
			}
			// Only worth saying when the file DID declare the object before:
			// a values file never did, and telling a reviewer that a
			// values.yaml still fails to declare a Deployment is noise.
			if declaresObject(before, object) && !declaresObject(docs, object) {
				change.Advisories = append(change.Advisories, fmt.Sprintf("%s declared %s %s at the synced commit and no longer does — check that changing which object this file defines is intended", edit.Path, object.Kind, objectWhere(object)))
			} else if declaresObject(docs, object) {
				change.Checks = append(change.Checks, fmt.Sprintf("%s still declares %s %s (namespace %s)", edit.Path, object.Kind, object.Name, orDash(object.Namespace)))
			}
		}
	}

	verb := "changed"
	if created {
		verb = "created"
		change.Checks = append(change.Checks, fmt.Sprintf("%s does not exist at the synced commit and would be created by this change", edit.Path))
	}
	change.Checks = append(change.Checks, fmt.Sprintf("%s %s: %d line(s) added, %d line(s) removed — ARGUS computed this diff from the file at the synced commit and the content proposed for it, and makes no claim beyond it",
		edit.Path, verb, change.LinesAdded, change.LinesRemoved))
	return change, nil
}

// ApplyFileDelete checks one proposed deletion against the file as it is at
// the pinned commit and returns the diffed, checked result — ApplyFileEdit's
// counterpart for FileEdit.Delete, BACKLOG.md "still open" #2.
//
// original is the file's CURRENT bytes at the synced commit, and must be
// non-empty: prepareChanges is responsible for refusing a delete of a path
// that does not exist there (scm.ErrNotFound) before this is ever called —
// there is no "created" case to mirror here, because a file that does not
// exist cannot be deleted. object is used only for the advisory identity
// note, exactly as ApplyFileEdit uses it.
func ApplyFileDelete(original []byte, path string, object ObjectRef) (FileChange, error) {
	if len(bytes.TrimSpace(original)) == 0 {
		// Reachable only if a caller passes an empty read without going
		// through prepareChanges' own ErrNotFound handling first — refused
		// rather than silently treated as "nothing to delete", matching this
		// package's convention of never guessing at an empty-content case.
		return FileChange{}, fmt.Errorf("%w: cannot delete %s — its current content at the synced commit is empty, which is not a state this package treats as \"the file exists\"", ErrVerificationFailed, path)
	}

	change := FileChange{
		Path:     path,
		Original: original,
		Deleted:  true,
	}
	beforeLines := strings.Split(string(original), "\n")
	change.Diff, change.LinesAdded, change.LinesRemoved = freeformUnifiedDiff(beforeLines, nil)
	change.LineCount = 0

	if docs, err := parseDocumentsStrict(original); err == nil {
		change.Parsed = true
		change.DocumentCount = 0
		if declaresObject(docs, object) {
			change.Advisories = append(change.Advisories, fmt.Sprintf("%s declares %s %s at the synced commit and would be REMOVED ENTIRELY by this change — check that deleting the object, not just editing it, is intended", path, object.Kind, objectWhere(object)))
		}
	}

	change.Checks = append(change.Checks, fmt.Sprintf("%s exists at the synced commit and would be DELETED by this change (%d line(s) removed)", path, change.LinesRemoved))
	return change, nil
}

// summarize folds per-file results into the proposal-level verification.
func summarize(files []FileChange) ChangeVerification {
	v := ChangeVerification{Files: files}
	multi := len(files) > 1
	for _, f := range files {
		if !f.Unchanged {
			v.FilesChanged++
			v.LinesAdded += f.LinesAdded
			v.LinesRemoved += f.LinesRemoved
		}
		for _, c := range f.Checks {
			v.Checks = append(v.Checks, prefixed(multi, f.Path, c))
		}
		for _, a := range f.Advisories {
			v.Advisories = append(v.Advisories, prefixed(multi, f.Path, a))
		}
	}
	return v
}

// prefixed keeps a single-file proposal's sentences reading naturally (they
// already name the file) while a multi-file one gets an explicit per-file
// grouping. The per-file sentences are written to stand alone, so this is only
// about keeping the aggregated list scannable.
func prefixed(multi bool, filePath, s string) string {
	if !multi || strings.HasPrefix(s, filePath) {
		return s
	}
	return filePath + ": " + s
}

// looksTemplated reports whether content carries Go template delimiters.
//
// Comments are stripped first, and that is not fussiness: a live run refused a
// perfectly ordinary Kustomize patch because a COMMENT in it mentioned
// "{{ }}". That mattered when this was a refusal; it still matters now that it
// selects between "parse failure is a refusal" and "parse failure is expected",
// because a plain manifest with a chatty comment must not have its parse
// failures excused.
func looksTemplated(content []byte) bool {
	return bytes.Contains(stripYAMLComments(content), []byte("{{"))
}

func hasYAMLExtension(filePath string) bool {
	ext := strings.ToLower(path.Ext(filePath))
	return ext == ".yaml" || ext == ".yml"
}

func declaresObject(docs []document, ref ObjectRef) bool {
	if ref.Kind == "" || ref.Name == "" {
		return false
	}
	for _, d := range docs {
		if documentMatches(d.node, ref) {
			return true
		}
	}
	return false
}

func objectWhere(ref ObjectRef) string {
	if ref.Namespace != "" {
		return ref.Namespace + "/" + ref.Name
	}
	return ref.Name
}

// normalizeTrailingNewline strips ALL trailing newlines for the "identical to
// the original" comparison, so a diff that is nothing but a text editor adding
// or removing the file's final newline is treated as no-op rather than as a
// change nobody meant to make. This affects only that comparison — the content
// committed is always the bytes exactly as submitted.
func normalizeTrailingNewline(b []byte) []byte {
	return bytes.TrimRight(b, "\n")
}

// stripYAMLComments blanks out comment text so a content scan sees only what
// the file actually declares.
//
// Quote-aware, because `name: "value # not a comment"` is a real thing and
// treating that `#` as a comment start would blank out declared content.
// Deliberately not a YAML parse: the files this runs against are frequently
// not valid YAML at all (that is the whole reason it works on bytes).
func stripYAMLComments(content []byte) []byte {
	out := make([]byte, 0, len(content))
	var quote byte
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case quote != 0:
			// Inside a quoted scalar. YAML escapes differ between ' and ", but
			// for the purpose of finding the closing quote a backslash escape
			// only matters in double quotes.
			if c == '\\' && quote == '"' && i+1 < len(content) {
				out = append(out, c, content[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			// Skip to the end of the line, preserving the newline so line
			// numbers and structure are unchanged for anything downstream.
			for i < len(content) && content[i] != '\n' {
				i++
			}
			if i < len(content) {
				out = append(out, '\n')
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// parseDocumentsStrict parses every document in a byte slice and FAILS on
// invalid YAML.
//
// Deliberately unlike readDocuments, which returns what it managed to parse: a
// repository with one broken file should not make every object in its other
// files unlocatable, so tolerance is right when searching and strictness is
// right when deciding whether a proposed manifest can be applied at all.
func parseDocumentsStrict(src []byte) ([]document, error) {
	if len(src) > maxManifestBytes {
		return nil, fmt.Errorf("gitops: this file is %d bytes, over the %d-byte manifest bound", len(src), maxManifestBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var docs []document
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("gitops: this file is not valid YAML: %w", err)
		}
		content := &node
		line := node.Line
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			content = node.Content[0]
			line = content.Line
		}
		docs = append(docs, document{node: content, line: line})
	}
	return docs, nil
}

// LocateDocuments returns the indexes of the documents in one file's bytes
// that define ref.
//
// The in-memory counterpart to LocateIn, for the API-based path: by the time
// the pull-request path has a file's bytes there is no tree to walk, but the
// same "which document" question still has to be answered, and answered the
// same way.
func LocateDocuments(content []byte, ref ObjectRef) ([]int, error) {
	docs, err := parseDocumentsStrict(content)
	if err != nil {
		return nil, err
	}
	var out []int
	for i, d := range docs {
		if documentMatches(d.node, ref) {
			out = append(out, i)
		}
	}
	return out, nil
}

// SoleDocumentFor is LocateDocuments plus the refusal.
//
// One match is required. Zero means the file does not define this object; more
// than one means the file defines it twice and only a human can say which —
// the same refuse-rather-than-guess rule LocateIn's doc comment records after
// finding the same Deployment twice in Argo CD's own example repository.
//
// Used by file DISCOVERY, which answers "which file should the editor open for
// this incident's object". It is not part of the edit path any more: a
// whole-file edit to a values.yaml has no document to identify.
func SoleDocumentFor(content []byte, ref ObjectRef, filePath string) (int, error) {
	matches, err := LocateDocuments(content, ref)
	if err != nil {
		return 0, err
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return 0, fmt.Errorf("%w: %s does not define %s %s/%s at this revision — the object may be generated, or defined in a different file",
			ErrAmbiguousDocument, filePath, ref.Kind, ref.Namespace, ref.Name)
	default:
		return 0, fmt.Errorf("%w: %s defines %s %s/%s in %d separate documents (%v); a human must say which one is the source of truth",
			ErrAmbiguousDocument, filePath, ref.Kind, ref.Namespace, ref.Name, len(matches), matches)
	}
}
