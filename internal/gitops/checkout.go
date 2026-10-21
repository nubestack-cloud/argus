package gitops

// Reading a cloned checkout safely — the file-access half of BACKLOG.md F22
// piece 1's read-only repository tools.
//
// # Why here rather than in the package that serves the tools
//
// This package already owns "we have a sparse, shallow, pinned checkout on
// disk; walk it without letting anything escape it" — LocateIn does exactly
// that, including the symlink and ".." rules. Serving a file read from a
// second package with its own idea of confinement would be a second place for
// that rule to be got wrong, so the traversal rules live here, once, and
// internal/repotools formats what these return into a tool result.
//
// # What is bounded, and why each bound is where it is
//
// Repository content is untrusted input (DESIGN.md §18.7). None of the bounds
// below are security boundaries on their own — the confinement checks are —
// but every one of them stops a repository from deciding how much of the hub's
// memory, or of an investigation's context window, it gets to consume.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrOutsideCheckout is a path that escapes the checkout (or the directory the
// caller confined the read to). Refused rather than cleaned up: these paths
// originate in model output, and silently correcting a traversal attempt hides
// it. Sentinel so a caller can report it as a refusal rather than a read error.
var ErrOutsideCheckout = errors.New("gitops: path is outside the checked-out directory")

const (
	// maxCheckoutFileBytes bounds one file read from a checkout. Deliberately
	// the same bound readDocuments applies to a manifest: a "file" bigger than
	// this is a vendored blob or a data dump, and nothing an investigation
	// needs to read is on the other side of it.
	maxCheckoutFileBytes = maxManifestBytes

	// maxCheckoutListed bounds a directory listing. LocateIn's own walk is
	// bounded at 20 000 files for cost; a listing handed to a model is bounded
	// far lower because its cost is context window rather than CPU, and a
	// thousand-entry listing helps nobody read a chart.
	maxCheckoutListed = 2000
)

// CheckoutFile is one file's bytes, with what the caller needs to report it
// honestly.
type CheckoutFile struct {
	// Path is repository-relative, forward slashes — the same shape
	// SourceLocation.Path uses, so a path from a listing can be handed
	// straight back as a read.
	Path string
	// Content is the file's bytes, whole. Slicing to a line window is the
	// caller's job; this either returns the file or refuses it.
	Content []byte
	// TotalLines is how many lines it has, so a caller windowing the content
	// can say what it left out.
	TotalLines int
}

// ReadCheckoutFile reads one file from a checkout, confined to root and,
// when confineTo is non-empty, to that subdirectory of root.
//
// Refuses, rather than returns, for: a path escaping the confinement, a
// symlink (never followed — the containment property that matters once these
// repositories are attacker-influenced, same rule LocateIn applies), a
// directory, a file over the size bound, and content that is not valid UTF-8.
// The last is not squeamishness: a binary blob in a model's context is spent
// budget with no information in it, and reporting "this is not text" is a more
// useful answer than several kilobytes of mojibake.
func ReadCheckoutFile(root, confineTo, rel string) (CheckoutFile, error) {
	full, clean, err := resolveWithin(root, confineTo, rel)
	if err != nil {
		return CheckoutFile{}, err
	}
	// Lstat, not Stat: a symlink must be identified as one rather than
	// followed to whatever it points at.
	info, err := os.Lstat(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return CheckoutFile{}, fmt.Errorf("%s does not exist at this revision", clean)
		}
		return CheckoutFile{}, fmt.Errorf("read %s: %w", clean, err)
	}
	if info.IsDir() {
		return CheckoutFile{}, fmt.Errorf("%s is a directory, not a file", clean)
	}
	if !info.Mode().IsRegular() {
		return CheckoutFile{}, fmt.Errorf("%s is not a regular file (it may be a symlink, which is never followed)", clean)
	}
	if info.Size() > maxCheckoutFileBytes {
		return CheckoutFile{}, fmt.Errorf("%s is %d bytes, over the %d-byte bound for a single file", clean, info.Size(), int64(maxCheckoutFileBytes))
	}
	content, err := os.ReadFile(full) //nolint:gosec // full is resolveWithin's confined result
	if err != nil {
		return CheckoutFile{}, fmt.Errorf("read %s: %w", clean, err)
	}
	if !utf8.Valid(content) {
		return CheckoutFile{}, fmt.Errorf("%s is not UTF-8 text, so there is nothing readable in it", clean)
	}
	return CheckoutFile{Path: clean, Content: content, TotalLines: strings.Count(string(content), "\n") + 1}, nil
}

// CheckoutEntry is one file in a listing.
type CheckoutEntry struct {
	Path  string
	Bytes int64
}

// CheckoutListing is what ListCheckoutFiles found. TotalMatched and Truncated
// are separate from the returned slice for the same reason list_resources
// reports them: a model that believes a truncated list was the complete list
// reasons from absence, and "not there" must never be indistinguishable from
// "we stopped looking".
type CheckoutListing struct {
	Dir          string
	Entries      []CheckoutEntry
	TotalMatched int
	Truncated    bool
}

// ListCheckoutFiles lists regular files under root/confineTo/subdir, sorted by
// path, capped at limit.
//
// Directories are not returned as entries — a path is only useful here if it
// can be read — but the walk descends into them, so a chart's templates/ shows
// up as its files. .git is skipped for the same reason LocateIn skips it.
func ListCheckoutFiles(root, confineTo, subdir string, limit int) (CheckoutListing, error) {
	if limit <= 0 || limit > maxCheckoutListed {
		limit = maxCheckoutListed
	}
	full, clean, err := resolveWithin(root, confineTo, subdir)
	if err != nil {
		return CheckoutListing{}, err
	}
	info, err := os.Stat(full)
	if err != nil || !info.IsDir() {
		return CheckoutListing{}, fmt.Errorf("%s is not a directory at this revision", displayDir(clean))
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return CheckoutListing{}, fmt.Errorf("resolve root: %w", err)
	}
	out := CheckoutListing{Dir: displayDir(clean)}
	walkErr := filepath.WalkDir(full, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is skipped, not fatal — the same judgement
			// LocateIn makes: a partial listing beats no listing.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are reported by DirEntry as themselves, so a link is simply
		// not a regular file and never listed — which also means a link
		// pointing outside the checkout can never be offered as readable.
		if !d.Type().IsRegular() {
			return nil
		}
		out.TotalMatched++
		if len(out.Entries) >= limit {
			out.Truncated = true
			return nil
		}
		rel, relErr := filepath.Rel(rootAbs, p)
		if relErr != nil {
			return nil
		}
		var size int64
		if fi, statErr := d.Info(); statErr == nil {
			size = fi.Size()
		}
		out.Entries = append(out.Entries, CheckoutEntry{Path: filepath.ToSlash(rel), Bytes: size})
		return nil
	})
	if walkErr != nil {
		return CheckoutListing{}, fmt.Errorf("list %s: %w", out.Dir, walkErr)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	return out, nil
}

// resolveWithin turns a caller-supplied repository-relative path into an
// absolute one inside root (and inside confineTo, when set), or refuses.
//
// A path is accepted in either of the two forms a model naturally produces:
// repository-relative ("charts/web/values.yaml") or relative to the confined
// directory ("values.yaml" when confineTo is "charts/web"). Accepting both is
// not laxity — the confinement is re-checked on the resolved result either
// way, so the worst a wrong guess produces is a "does not exist", never an
// escape — and refusing one of them would make the tools fail on exactly the
// paths a model is most likely to write.
func resolveWithin(root, confineTo, rel string) (fullPath, cleanRel string, err error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve root: %w", err)
	}
	confine := strings.Trim(strings.TrimSpace(filepath.ToSlash(confineTo)), "/")
	if confine == "." {
		confine = ""
	}
	candidate := strings.Trim(strings.TrimSpace(filepath.ToSlash(rel)), "/")

	// Refused before any join: a ".." segment is a traversal attempt whatever
	// filepath.Join would make of it afterwards.
	for _, seg := range strings.Split(candidate, "/") {
		if seg == ".." {
			return "", "", fmt.Errorf("%w: %q contains a \"..\" segment", ErrOutsideCheckout, rel)
		}
	}
	if filepath.IsAbs(rel) {
		return "", "", fmt.Errorf("%w: %q is an absolute path", ErrOutsideCheckout, rel)
	}

	// Two readings of the same string, repository-relative preferred: if the
	// model already wrote the full path, honour it; otherwise treat it as
	// relative to the synced directory.
	cleanRel = candidate
	if confine != "" && candidate != confine && !strings.HasPrefix(candidate, confine+"/") {
		cleanRel = strings.TrimSuffix(confine+"/"+candidate, "/")
	}
	cleanRel = strings.TrimSuffix(cleanRel, "/")

	full := filepath.Join(rootAbs, filepath.FromSlash(cleanRel))
	if !isWithin(rootAbs, full) {
		return "", "", fmt.Errorf("%w: %q resolves outside the checkout", ErrOutsideCheckout, rel)
	}
	if confine != "" {
		confineAbs := filepath.Join(rootAbs, filepath.FromSlash(confine))
		if !isWithin(confineAbs, full) {
			return "", "", fmt.Errorf("%w: %q resolves outside %s, the directory this object's GitOps controller reports syncing", ErrOutsideCheckout, rel, confine)
		}
	}
	return full, cleanRel, nil
}

func displayDir(clean string) string {
	if clean == "" {
		return "the repository root"
	}
	return clean
}
