package helmstatus

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeGetter serves a contiguous range of revisions [lo, hi] for one release
// and counts gets.
type fakeGetter struct {
	release string
	lo, hi  int
	status  map[int]string
	labels  map[int]map[string]string // overrides
	created map[int]time.Time         // metadata.creationTimestamp
	gets    int
	names   []string
	err     error
}

func (f *fakeGetter) GetSecretMeta(_ context.Context, _ string, name string) (SecretMeta, bool, error) {
	f.gets++
	f.names = append(f.names, name)
	if f.err != nil {
		return SecretMeta{}, false, f.err
	}
	for n := f.lo; n <= f.hi && f.hi > 0; n++ {
		if SecretName(f.release, n) != name {
			continue
		}
		if l, ok := f.labels[n]; ok {
			return SecretMeta{Labels: l, CreationTimestamp: f.created[n]}, true, nil
		}
		status := f.status[n]
		if status == "" {
			status = "superseded"
			if n == f.hi {
				status = "deployed"
			}
		}
		return SecretMeta{Labels: map[string]string{
			"name":       f.release,
			"owner":      "helm",
			"status":     status,
			"version":    strconv.Itoa(n),
			"modifiedAt": strconv.FormatInt(testNow.Add(-time.Duration(f.hi-n)*time.Hour).Unix(), 10),
		}, CreationTimestamp: f.created[n]}, true, nil
	}
	return SecretMeta{}, false, nil
}

func TestSecretName(t *testing.T) {
	if got := SecretName("cart", 7); got != "sh.helm.release.v1.cart.v7" {
		t.Fatalf("SecretName = %q", got)
	}
}

func TestLatestRevisionFindsContiguousTop(t *testing.T) {
	// Twelve gets pin any latest revision up to 32 from a cold start; larger
	// histories need a budget that covers the extra doubling and halving.
	for _, tc := range []struct{ hi, budget int }{
		{1, 12}, {2, 12}, {3, 12}, {5, 12}, {9, 12}, {10, 12}, {17, 12}, {32, 12}, {33, 14}, {63, 14},
	} {
		hi := tc.hi
		g := &fakeGetter{release: "cart", lo: 1, hi: hi}
		got, err := LatestRevision(context.Background(), g, "shop", "cart", tc.budget)
		if err != nil {
			t.Fatalf("hi=%d: err = %v", hi, err)
		}
		if got != hi {
			t.Fatalf("hi=%d: LatestRevision = %d", hi, got)
		}
		if g.gets > tc.budget {
			t.Fatalf("hi=%d: %d gets, budget %d", hi, g.gets, tc.budget)
		}
	}
}

func TestLatestRevisionWithPrunedHistory(t *testing.T) {
	// History-max pruned revisions below 12; probes 1,2,3,5,9 miss, 17 hits.
	g := &fakeGetter{release: "cart", lo: 12, hi: 21}
	got, err := LatestRevision(context.Background(), g, "shop", "cart", 12)
	if err != nil || got != 21 {
		t.Fatalf("LatestRevision = %d, %v; want 21", got, err)
	}
}

func TestLatestRevisionNotFound(t *testing.T) {
	g := &fakeGetter{release: "cart"}
	_, err := LatestRevision(context.Background(), g, "shop", "cart", 6)
	if !errors.Is(err, ErrNoRevisionFound) {
		t.Fatalf("err = %v, want ErrNoRevisionFound", err)
	}
	if g.gets != 6 {
		t.Fatalf("gets = %d, want the whole budget of 6", g.gets)
	}
}

func TestLatestRevisionBudgetExhaustedReturnsLowerBound(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 1, hi: 100}
	got, err := LatestRevision(context.Background(), g, "shop", "cart", 4)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if got < 1 || got > 100 {
		t.Fatalf("lower bound = %d, want within [1,100]", got)
	}
	if g.gets != 4 {
		t.Fatalf("gets = %d, want 4", g.gets)
	}
}

func TestLatestRevisionFromHint(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 90, hi: 101}
	got, err := LatestRevisionFrom(context.Background(), g, "shop", "cart", 100, 12)
	if err != nil || got != 101 {
		t.Fatalf("LatestRevisionFrom = %d, %v; want 101", got, err)
	}
	if g.gets > 4 {
		t.Fatalf("a fresh hint should be cheap, used %d gets", g.gets)
	}

	unchanged := &fakeGetter{release: "cart", lo: 90, hi: 100}
	if got, err := LatestRevisionFrom(context.Background(), unchanged, "shop", "cart", 100, 12); err != nil || got != 100 || unchanged.gets != 2 {
		t.Fatalf("unchanged release = %d, %v in %d gets; want 100 in 2", got, err, unchanged.gets)
	}
}

func TestLatestRevisionFromStaleHintAfterReinstall(t *testing.T) {
	// Release was uninstalled and reinstalled: revisions restart at 1.
	g := &fakeGetter{release: "cart", lo: 1, hi: 3}
	got, err := LatestRevisionFrom(context.Background(), g, "shop", "cart", 40, 12)
	if err != nil || got != 3 {
		t.Fatalf("LatestRevisionFrom = %d, %v; want 3", got, err)
	}
	if g.gets > 12 {
		t.Fatalf("gets = %d over budget", g.gets)
	}
}

func TestLatestRevisionPropagatesGetterError(t *testing.T) {
	g := &fakeGetter{release: "cart", err: errors.New("forbidden")}
	if _, err := LatestRevision(context.Background(), g, "shop", "cart", 12); err == nil || errors.Is(err, ErrNoRevisionFound) {
		t.Fatalf("err = %v, want the getter error", err)
	}
	if g.gets != 1 {
		t.Fatalf("gets = %d, want to stop at the first error", g.gets)
	}
}

func TestLatestRevisionRejectsBadArgs(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 1, hi: 1}
	if _, err := LatestRevision(context.Background(), g, "shop", "", 12); err == nil {
		t.Fatal("empty release accepted")
	}
	if _, err := LatestRevision(context.Background(), g, "shop", "cart", 0); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("zero budget err = %v", err)
	}
}

func TestHistoryReadsLabelsOldestFirst(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 1, hi: 5, status: map[int]string{4: "failed"}}
	got, err := History(context.Background(), g, "shop", "cart", 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Revision != 3 || got[2].Revision != 5 {
		t.Fatalf("History = %#v, want revisions 3..5", got)
	}
	if got[1].Status != "failed" || got[2].Status != "deployed" {
		t.Fatalf("statuses = %q,%q", got[1].Status, got[2].Status)
	}
	if !got[2].Updated.Equal(testNow) {
		t.Fatalf("updated = %v, want %v", got[2].Updated, testNow)
	}
	if got[0].Chart != "" || got[0].AppVersion != "" {
		t.Fatal("chart/app version must stay empty from metadata")
	}
	if g.gets != 3 {
		t.Fatalf("gets = %d, want 3", g.gets)
	}
}

func TestHistoryStopsAtPrunedRevision(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 4, hi: 6}
	got, err := History(context.Background(), g, "shop", "cart", 6, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Revision != 4 {
		t.Fatalf("History = %#v, want 4..6", got)
	}
	if g.gets != 4 {
		t.Fatalf("gets = %d, want 4 (3 hits + the miss that ends the walk)", g.gets)
	}
}

func TestHistorySkipsMismatchedLabelsAndFallsBackToCreatedAt(t *testing.T) {
	created := testNow.Add(-20 * time.Minute)
	g := &fakeGetter{release: "cart", lo: 1, hi: 4, labels: map[int]map[string]string{
		4: {"name": "cart", "owner": "helm", "status": "pending-upgrade", "version": "4",
			"createdAt": strconv.FormatInt(created.Unix(), 10)},
		3: {"name": "other", "owner": "helm", "status": "deployed", "version": "3"},
		2: {"name": "cart", "owner": "someone", "status": "deployed", "version": "2"},
		1: {"name": "cart", "owner": "helm", "status": "superseded", "version": "7"},
	}}
	got, err := History(context.Background(), g, "shop", "cart", 4, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Revision != 4 {
		t.Fatalf("History = %#v, want only revision 4", got)
	}
	if !got[0].Updated.Equal(created) {
		t.Fatalf("updated = %v, want createdAt %v", got[0].Updated, created)
	}
	a := Analyze("cart", 4, got, Options{Now: testNow})
	if a.LastOperation == nil || a.LastOperation.Kind != KindPending {
		t.Fatalf("stuck pending not detected from createdAt: %#v", a.LastOperation)
	}
}

func TestHistoryEmptyArgs(t *testing.T) {
	g := &fakeGetter{release: "cart", lo: 1, hi: 3}
	if got, err := History(context.Background(), g, "shop", "cart", 0, 10); err != nil || got != nil {
		t.Fatalf("History(latest=0) = %v, %v", got, err)
	}
	if got, err := History(context.Background(), g, "shop", "cart", 3, 0); err != nil || got != nil {
		t.Fatalf("History(limit=0) = %v, %v", got, err)
	}
	if g.gets != 0 {
		t.Fatalf("gets = %d, want 0", g.gets)
	}
}

func TestHistoryGetterError(t *testing.T) {
	g := &fakeGetter{release: "cart", err: errors.New("boom")}
	if _, err := History(context.Background(), g, "shop", "cart", 3, 3); err == nil {
		t.Fatal("expected error")
	}
}

// shop-apps in default on lab-dev: every revision's Secret carries the same
// modifiedAt label (1773839038, 2026-03-18) while the Secrets themselves
// were created months apart — v18 on 2026-10-05. The revision's date must
// come from metadata.creationTimestamp; Helm's label is kept as-is beside it.
func TestHistoryDatesRevisionsByCreationNotStaleModifiedAt(t *testing.T) {
	stale := "1773839038"
	labels := func(n int, status string) map[string]string {
		return map[string]string{"name": "shop-apps", "owner": "helm", "status": status, "version": strconv.Itoa(n), "modifiedAt": stale}
	}
	v17 := time.Date(2026, 8, 28, 13, 2, 45, 0, time.UTC)
	v18 := time.Date(2026, 10, 5, 12, 36, 18, 0, time.UTC)
	g := &fakeGetter{release: "shop-apps", lo: 9, hi: 18,
		labels:  map[int]map[string]string{17: labels(17, "superseded"), 18: labels(18, "deployed")},
		created: map[int]time.Time{17: v17, 18: v18},
	}
	got, err := History(context.Background(), g, "default", "shop-apps", 18, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("History = %#v, %v", got, err)
	}
	staleAt := time.Unix(1773839038, 0).UTC()
	for i, want := range []time.Time{v17, v18} {
		r := got[i]
		if !r.CreatedAt.Equal(want) || !r.Updated.Equal(want) {
			t.Errorf("v%d createdAt=%v updated=%v, want both %v", r.Revision, r.CreatedAt, r.Updated, want)
		}
		if !r.ModifiedAt.Equal(staleAt) {
			t.Errorf("v%d modifiedAt=%v, want Helm's label %v kept verbatim", r.Revision, r.ModifiedAt, staleAt)
		}
	}
	b, _ := json.Marshal(got[1])
	if !strings.Contains(string(b), `"createdAt":"2026-10-05T12:36:18Z"`) || !strings.Contains(string(b), `"modifiedAt":"2026-03-18T`) {
		t.Errorf("JSON = %s", b)
	}
}
