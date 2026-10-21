package helmstatus

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// SecretMeta is the metadata of one release Secret that crosses
// SecretMetaGetter: its labels and its metadata.creationTimestamp. Nothing
// from the payload.
type SecretMeta struct {
	Labels            map[string]string
	CreationTimestamp time.Time
}

// SecretMetaGetter fetches one named Secret's metadata. Implementations must
// discard the Secret's data in the same function that receives it; only
// SecretMeta crosses this interface. found=false with a nil error means the
// Secret does not exist.
type SecretMetaGetter interface {
	GetSecretMeta(ctx context.Context, namespace, name string) (meta SecretMeta, found bool, err error)
}

var (
	// ErrNoRevisionFound means no revision Secret was found within the get
	// budget: the release does not exist in that namespace, or its surviving
	// revisions (Helm prunes the oldest beyond --history-max) all fall
	// between probe points. A cached previous latest revision passed to
	// LatestRevisionFrom avoids the second case.
	ErrNoRevisionFound = errors.New("helmstatus: no release revision found")
	// ErrBudgetExhausted means the search ran out of gets after finding a
	// revision but before pinning the latest; the revision returned with it
	// is a lower bound.
	ErrBudgetExhausted = errors.New("helmstatus: get budget exhausted before the latest revision was pinned")
)

// maxRevision bounds the search so a pathological getter that reports every
// name as present cannot overflow the probe arithmetic.
const maxRevision = 1 << 30

// SecretName is the name Helm's Secret storage driver gives one revision.
func SecretName(release string, revision int) string {
	return fmt.Sprintf("sh.helm.release.v1.%s.v%d", release, revision)
}

// LatestRevision finds the highest existing revision of a release by named
// gets only — no Secret listing. See LatestRevisionFrom.
func LatestRevision(ctx context.Context, g SecretMetaGetter, ns, release string, maxGets int) (int, error) {
	return LatestRevisionFrom(ctx, g, ns, release, 0, maxGets)
}

// LatestRevisionFrom finds the highest existing revision, starting from hint
// (a previously found latest revision; 0 or less means start at 1). Helm keeps
// a contiguous range of revisions, pruning the oldest, so the search probes
// exponentially growing offsets above the start until it sees a miss after a
// hit, then binary-searches between the last hit and that miss. At most
// maxGets gets are issued. If a hint misses and nothing above it is found, the
// release was reset (uninstalled and reinstalled), and the search restarts
// from 1 with the remaining budget.
func LatestRevisionFrom(ctx context.Context, g SecretMetaGetter, ns, release string, hint, maxGets int) (int, error) {
	if release == "" {
		return 0, errors.New("helmstatus: empty release name")
	}
	if maxGets <= 0 {
		return 0, ErrBudgetExhausted
	}
	gets := 0
	probe := func(n int) (bool, error) {
		gets++
		_, found, err := g.GetSecretMeta(ctx, ns, SecretName(release, n))
		if err != nil {
			return false, fmt.Errorf("helmstatus: get revision %d of %s/%s: %w", n, ns, release, err)
		}
		return found, nil
	}

	starts := []int{1}
	if hint > 1 {
		starts = []int{hint, 1}
	}
	for i, start := range starts {
		// A missing hint means the release was either reinstalled (revisions
		// restart at 1) or pruned past the hint; spend at most half of the
		// remaining budget looking upward before trying from 1.
		limit := maxGets
		lo, hi := 0, 0
		for off := 0; gets < limit; {
			n := start + off
			if n > maxRevision {
				break
			}
			hit, err := probe(n)
			if err != nil {
				return lo, err
			}
			if hit {
				lo = n
			} else if lo > 0 {
				hi = n
				break
			} else if off == 0 && i+1 < len(starts) {
				limit = gets + (maxGets-gets)/2
			}
			if off == 0 {
				off = 1
			} else {
				off *= 2
			}
		}
		if lo == 0 {
			continue
		}
		if hi == 0 {
			return lo, ErrBudgetExhausted
		}
		for hi-lo > 1 {
			if gets >= maxGets {
				return lo, ErrBudgetExhausted
			}
			mid := lo + (hi-lo)/2
			hit, err := probe(mid)
			if err != nil {
				return lo, err
			}
			if hit {
				lo = mid
			} else {
				hi = mid
			}
		}
		return lo, nil
	}
	return 0, ErrNoRevisionFound
}

// History reads up to limit revisions ending at latest, oldest first, from
// their Secrets' metadata: the name, owner, status, version, modifiedAt and
// createdAt labels, and metadata.creationTimestamp. A revision whose Secret
// is missing ends the walk, since Helm prunes from the oldest end. A Secret
// whose labels do not describe this release's revision (wrong name, version,
// or a non-Helm owner) is skipped rather than trusted.
func History(ctx context.Context, g SecretMetaGetter, ns, release string, latest, limit int) ([]Revision, error) {
	if latest <= 0 || limit <= 0 {
		return nil, nil
	}
	var out []Revision
	for n := latest; n >= 1 && latest-n < limit; n-- {
		meta, found, err := g.GetSecretMeta(ctx, ns, SecretName(release, n))
		if err != nil {
			return reverse(out), fmt.Errorf("helmstatus: get revision %d of %s/%s: %w", n, ns, release, err)
		}
		if !found {
			break
		}
		rev, ok := revisionFromMeta(release, n, meta)
		if !ok {
			continue
		}
		out = append(out, rev)
	}
	return reverse(out), nil
}

// revisionFromMeta builds a Revision from a release Secret's metadata.
//
// CreatedAt is the Secret's metadata.creationTimestamp — when this revision
// was written, set by the API server and so reliable (Helm's own createdAt
// label is the fallback when it is absent). ModifiedAt is Helm's modifiedAt
// label as Helm wrote it; it is not trustworthy as a per-revision time: on
// real clusters every revision of a release has been observed carrying the
// same stale value. Updated is the latest of the three, so a stale
// modifiedAt can never make a revision look older than its own creation,
// while a genuine later status change (pending-upgrade → deployed) still
// moves it forward. A revision never updated since creation — the stuck
// pending-* case — is therefore dated by its creation.
func revisionFromMeta(release string, n int, meta SecretMeta) (Revision, bool) {
	labels := meta.Labels
	if labels == nil {
		return Revision{}, false
	}
	if name := labels["name"]; name != "" && name != release {
		return Revision{}, false
	}
	if owner := labels["owner"]; owner != "" && owner != "helm" {
		return Revision{}, false
	}
	if v := labels["version"]; v != "" {
		if parsed, err := strconv.Atoi(v); err != nil || parsed != n {
			return Revision{}, false
		}
	}
	rev := Revision{Revision: n, Status: labels["status"]}
	unixLabel := func(key string) time.Time {
		if ts, err := strconv.ParseInt(labels[key], 10, 64); err == nil && ts > 0 {
			return time.Unix(ts, 0).UTC()
		}
		return time.Time{}
	}
	rev.ModifiedAt = unixLabel("modifiedAt")
	rev.CreatedAt = meta.CreationTimestamp.UTC()
	if meta.CreationTimestamp.IsZero() {
		rev.CreatedAt = unixLabel("createdAt")
	}
	for _, t := range []time.Time{rev.CreatedAt, unixLabel("createdAt"), rev.ModifiedAt} {
		if t.After(rev.Updated) {
			rev.Updated = t
		}
	}
	return rev, true
}

func reverse(revs []Revision) []Revision {
	for i, j := 0, len(revs)-1; i < j; i, j = i+1, j-1 {
		revs[i], revs[j] = revs[j], revs[i]
	}
	return revs
}
