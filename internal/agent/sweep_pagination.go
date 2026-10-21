package agent

// sweep_pagination.go is PROJECT.md P17(c): `Limit`-based pagination for the
// sweep's cluster-wide reads, and — more importantly — the rule that decides
// WHICH reads get it.
//
// # Why this could not be stacked on P17(b)
//
// P17(b) made every sweep read a watch-cache read (`ResourceVersion: "0"`),
// which is one request served without touching etcd. The API server IGNORES
// `Limit` for such a request: it hands back the entire collection. Verified
// against this repo's disposable kind cluster on Kubernetes v1.34.0
// (2026-09-25):
//
//	GET /api/v1/pods?resourceVersion=0&limit=100  -> 2030 items, no continue
//	GET /api/v1/pods?limit=100                    -> 100 items, continue set,
//	                                                 remainingItemCount 1930
//
// So each read has to CHOOSE. It cannot have both.
//
// # What each side of that choice actually buys
//
// Watch cache: one request, no etcd read, no quorum. Cheapest possible thing
// to ask an API server for. Cost: the response is unbounded, so the client
// must have room for the whole collection decoded at once, and the API
// server must build the whole response at once too.
//
// Pagination: the peak is bounded. Measured on the 2,030-pod cluster, one
// unpaginated unstructured Pod list retains ~99Mi and peaks at ~245Mi —
// two and a half times what it keeps, because the entire response body is
// decoded inside a single json.Unmarshal the collector cannot get ahead of.
// The same read in pages peaks at what it has retained so far plus ONE
// page's decode. Cost: the first page is a quorum read through to etcd and
// each subsequent page is another request, so P17(b)'s saving is given back
// for that kind on that pass.
//
// Note what pagination does NOT buy, because the board item's framing
// invites the wrong conclusion: it does not reduce the bytes that cross the
// wire. The checkers need the objects, so the objects travel either way.
// What changes is that no single response is unbounded — on the client, on
// the API server, and on the network buffer in between.
//
// # The rule
//
// Pagination is an ESCALATION, not a default. A read is issued:
//
//  1. from the watch cache, when the guard has no size estimate for the kind
//     (the common case — sweepMemoryGuard.projectFor prices Pods and nothing
//     else) or when the estimate says the unpaginated read comfortably fits.
//     Every cluster inside the chart's own sizing rule stays here, and gives
//     up nothing P17(b) won.
//  2. paginated, when the estimate says the unpaginated read does NOT fit but
//     the objects it would retain still would. This is the case that used to
//     be a refusal — or, before PROJECT.md B187 was fixed, an OOMKill.
//  3. not at all, when even the retained objects do not fit. Pagination
//     cannot help there and the refusal says so.
//
// That ordering is the whole design: an agent sized correctly for its cluster
// behaves exactly as it did after P17(b), and an agent that is NOT sized
// correctly trades API-server cost for the ability to complete the read at
// all, instead of reporting nothing.
//
// # Pagination replaces prediction with measurement
//
// The guard's estimate is a pod count times a bytes-per-object constant, and
// that constant is a lie on any cluster whose objects are fatter than the
// ones it was measured against. A paginated read does not have to keep
// guessing: every page carries `remainingItemCount`, so after the FIRST page
// the agent knows exactly how many objects are left and re-checks the budget
// against that real number (see pagedRead.next). A read whose objects turn
// out to be three times the assumed size is stopped after one page rather
// than after all of them. This is what P17(c) means by bounding a peak
// rather than predicting it.

import (
	"context"
	"fmt"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sweepPageSize is how many objects one page asks for when a read is
// paginated. 500 is the Kubernetes convention — kubectl's default chunk size
// and every reflector's — so it is the size an API server's own caches and
// limits are tuned for, and picking a different number would be this
// codebase inventing a constant where the ecosystem already has one.
//
// It is also the number that appears in the guard's arithmetic: the whole
// point of a page is that its decode cost is fixed and known, so the
// transient headroom a paginated read needs is sweepPageSize objects' worth
// of decode rather than the whole collection's (see pagedHeadroomFactor).
const sweepPageSize = 500

// sweepReadPlan is how one cluster-wide read was decided. The zero value is
// the unpaginated watch-cache read, which is what every read does when there
// is no memory guard at all (a host-run agent, every unit test), so a plan
// nobody filled in behaves exactly as the code did before P17(c).
type sweepReadPlan struct {
	// paginate is true when this read must go page by page. It implies
	// giving up the watch cache: listOptions() drops ResourceVersion, because
	// keeping it would silently disable the Limit and hand back everything.
	paginate bool

	// perObject is the guard's bytes-per-object constant for this read's
	// representation (typed or unstructured), carried so that the per-page
	// re-check can price what the server says is REMAINING rather than what
	// the pass assumed at the start.
	perObject uint64

	// what names the read the way the refusal message does, so a mid-read
	// stop reads the same as a pre-read refusal.
	what string

	// guard is the guard that produced this plan, or nil. Held so a paged
	// read can re-check between pages without every call site threading the
	// guard through as a second argument.
	guard *sweepMemoryGuard
}

// listOptions is the ListOptions the first request of this read should use.
//
// The unpaginated case is sweepListOptions verbatim (P17(b)'s watch-cache
// read). The paginated case deliberately sets NO ResourceVersion: the API
// server ignores Limit when one is present, so asking for both would quietly
// produce the unbounded read this plan exists to avoid — the failure would be
// invisible, because the response is a perfectly valid list.
func (p sweepReadPlan) listOptions() metav1.ListOptions {
	if !p.paginate {
		return sweepListOptions
	}
	return metav1.ListOptions{Limit: sweepPageSize}
}

// pagedHeadroomFactor is the effective decode headroom factor for a
// paginated read of projected bytes.
//
// A paginated read holds everything it has decoded so far and, on top of
// that, the in-flight decode of exactly one page — so its transient cost is
// one page's worth of churn, not the whole collection's. Expressed as a
// multiplier on the projected total (which is what admit takes), that is:
//
//	1 + (one page's bytes / projected) * (singleListDecodeHeadroomFactor - 1)
//
// On the 2,030-pod cluster, an unstructured Pod read projects 99Mi and one
// 500-object page is 24Mi, so the factor is 1 + 0.246*1.6 = 1.39 against
// 2.6 unpaginated. The bigger the collection, the closer this gets to 1 —
// which is the property that makes pagination a BOUND rather than a better
// guess.
//
// Returns the unpaginated factor when there is nothing to divide by, so a
// read with no estimate is never made to look cheaper than one with one.
func pagedHeadroomFactor(projected, perObject uint64) float64 {
	if projected == 0 || perObject == 0 {
		return singleListDecodeHeadroomFactor
	}
	pageBytes := float64(sweepPageSize * perObject)
	if pageBytes >= float64(projected) {
		// Fewer objects than one page: pagination would be a single request
		// that is not actually a page, so it saves nothing and should not be
		// priced as if it did.
		return singleListDecodeHeadroomFactor
	}
	return 1 + (pageBytes/float64(projected))*(singleListDecodeHeadroomFactor-1)
}

// planList is planRead for a single cluster-wide list of one kind, priced at
// the single-list rate.
func (g *sweepMemoryGuard) planList(what, kind string, perObject uint64) (sweepReadPlan, error) {
	if g == nil {
		return sweepReadPlan{}, nil
	}
	return g.planRead(what, g.projectFor(kind, perObject), perObject, singleListDecodeHeadroomFactor)
}

// planRead is the decision described at the top of this file: watch cache,
// paginated, or refused, in that order of preference.
//
// unpaginatedFactor is the headroom the read needs if it is issued whole —
// singleListDecodeHeadroomFactor for one list, multiKindDecodeHeadroomFactor
// for the many-kind pass. Pagination's own factor does not depend on which,
// because a page is a page.
func (g *sweepMemoryGuard) planRead(what string, projected, perObject uint64, unpaginatedFactor float64) (sweepReadPlan, error) {
	if g == nil || g.budget == 0 {
		return sweepReadPlan{}, nil
	}
	// 1. Whole, from the watch cache, if it fits. This is the path every
	//    correctly-sized agent takes for every read, every pass.
	if _, ok := g.fits(projected, unpaginatedFactor); ok {
		return sweepReadPlan{}, nil
	}
	// 2. Paginated, if the objects themselves still fit. fits re-does the
	//    live-heap reading (and, at most once a pass, the forced collection)
	//    rather than reusing the one above, because the first call may have
	//    just collected and freed the room this one needs.
	paged := pagedHeadroomFactor(projected, perObject)
	if paged < unpaginatedFactor {
		if _, ok := g.fits(projected, paged); ok {
			g.paginated++
			return sweepReadPlan{paginate: true, perObject: perObject, what: what, guard: g}, nil
		}
	}
	// 3. Neither fits — ONE refused read, counted once however many shapes
	//    it was tried in. Reported against the CHEAPER of the two factors, so
	//    the number in the message is the one that actually decided it:
	//    telling an operator a read needed 258Mi when the agent had already
	//    tried and failed to fit a 138Mi paginated version of it would send
	//    them after the wrong limit.
	cheapest := unpaginatedFactor
	if paged < cheapest {
		cheapest = paged
	}
	live, _ := g.fits(projected, cheapest)
	return sweepReadPlan{}, g.refuse(what+" (in pages as well as whole)", projected, cheapest, live)
}

// --- driving a paginated read ---

// pagedRead is the loop state for one paginated cluster-wide list. Created by
// listPaged; not used directly.
type pagedRead struct {
	plan      sweepReadPlan
	retained  uint64 // bytes this read is estimated to be holding so far
	pages     int
	continued string
}

// next returns the options for the next request, or false when the read is
// complete. It is also where the plan's estimate stops mattering: `total` is
// the server's own remainingItemCount from the page just decoded, so from
// page two onwards the budget check is made against a real count.
func (r *pagedRead) next(remaining *int64) (metav1.ListOptions, bool, error) {
	if r.continued == "" {
		return metav1.ListOptions{}, false, nil
	}
	if r.plan.guard != nil && remaining != nil && *remaining > 0 {
		// What is LEFT, priced at the single-list rate for one page plus
		// whatever those objects will retain. If that no longer fits, stop
		// here rather than at the end: a partial list is not returned (the
		// caller discards it), so stopping early is strictly cheaper than
		// stopping late.
		left := uint64(*remaining) * r.plan.perObject
		if err := r.plan.guard.admit(fmt.Sprintf("%s, part-way through (stopped after %d page(s), with %d object(s) still to read)",
			r.plan.what, r.pages, *remaining), left, pagedHeadroomFactor(left, r.plan.perObject)); err != nil {
			return metav1.ListOptions{}, false, err
		}
	}
	return metav1.ListOptions{Limit: sweepPageSize, Continue: r.continued}, true, nil
}

// listPaged drives one cluster-wide read to completion under plan.
//
// fetch issues one request with the given options and returns the list it got
// back. For an unpaginated plan it is called exactly once, with
// sweepListOptions — which is the pre-P17(c) behaviour, reached through the
// same code path so there is no second, untested route for the common case.
//
// The pages are merged into the FIRST page's list object, in place, so what
// the caller gets back is one ordinary *SomethingList with every object in
// it and nothing else retained. Merging by appending to the first page's
// Items slice (rather than building a new list at the end) matters under a
// memory limit: a final copy would briefly hold two complete collections,
// which on the reads that need pagination is exactly the peak being avoided.
func listPaged[L any](ctx context.Context, plan sweepReadPlan, fetch func(context.Context, metav1.ListOptions) (L, error)) (L, error) {
	var zero L
	first, err := fetch(ctx, plan.listOptions())
	if err != nil {
		return zero, err
	}
	if !plan.paginate {
		return first, nil
	}
	read := &pagedRead{plan: plan, pages: 1}
	read.continued, err = listContinue(first)
	if err != nil {
		return zero, err
	}
	for {
		opts, more, err := read.next(listRemaining(first))
		if err != nil {
			return zero, err
		}
		if !more {
			// The merged list is complete, so it must not still advertise
			// the first page's continue token: a caller that believed it
			// would ask the API server for objects this list already holds.
			setListComplete(first)
			return first, nil
		}
		page, err := fetch(ctx, opts)
		if err != nil {
			return zero, err
		}
		if err := appendSweepListItems(first, page); err != nil {
			return zero, err
		}
		read.pages++
		if read.continued, err = listContinue(page); err != nil {
			return zero, err
		}
		// The page's own metadata replaces the first page's for the next
		// round-trip's remainingItemCount reading.
		setListRemaining(first, listRemaining(page))
	}
}

// listContinue reads a list's continue token.
//
// metav1.ListInterface rather than reflection on an embedded ListMeta: the
// two list shapes this package pages store their list metadata differently —
// a typed *corev1.PodList embeds metav1.ListMeta, while an
// *unstructured.UnstructuredList keeps it inside its Object map and has no
// such field at all — and the interface is the one thing both genuinely
// implement. (This was found the way such things are usually found: the
// reflection version compiled, passed every fake-client test, and failed
// only on the unstructured half, which is the half that needs pagination.)
//
// It is also deliberately not a type switch over the sixteen concrete list
// types, which would go stale the next time a kind is added to
// sweep_snapshot.go. TestEverySweepListTypeCanBePaged pins that every type
// this package pages satisfies it.
func listContinue(list any) (string, error) {
	meta, err := listMetaOf(list)
	if err != nil {
		return "", err
	}
	return meta.GetContinue(), nil
}

func listRemaining(list any) *int64 {
	meta, err := listMetaOf(list)
	if err != nil {
		return nil
	}
	return meta.GetRemainingItemCount()
}

// setListComplete clears the paging metadata a merged list inherited from
// its first page, so what the caller gets back describes itself honestly: a
// whole collection, with nothing left to fetch.
func setListComplete(list any) {
	if meta, err := listMetaOf(list); err == nil {
		meta.SetContinue("")
		meta.SetRemainingItemCount(nil)
	}
}

func setListRemaining(list any, remaining *int64) {
	if meta, err := listMetaOf(list); err == nil {
		meta.SetRemainingItemCount(remaining)
	}
}

// listMetaOf returns a list object's list metadata, however that object
// happens to store it.
func listMetaOf(list any) (metav1.ListInterface, error) {
	meta, ok := list.(metav1.ListInterface)
	if !ok {
		return nil, fmt.Errorf("paginated read: %T does not implement metav1.ListInterface, so its continue token cannot be followed", list)
	}
	return meta, nil
}

// appendSweepListItems appends src's Items onto dst's, in place.
//
// reflect.AppendSlice, not meta.ExtractList/meta.SetList: the apimachinery
// pair round-trips every item through a []runtime.Object of interface
// headers and then copies them all back, which on a read of several thousand
// objects across several pages is quadratic copying of exactly the objects
// this read is trying not to duplicate. AppendSlice is one amortised memmove
// per page.
func appendSweepListItems(dst, src any) error {
	dstItems, err := itemsField(dst)
	if err != nil {
		return err
	}
	srcItems, err := itemsField(src)
	if err != nil {
		return err
	}
	if dstItems.Type() != srcItems.Type() {
		return fmt.Errorf("paginated read: cannot append %s onto %s", srcItems.Type(), dstItems.Type())
	}
	dstItems.Set(reflect.AppendSlice(dstItems, srcItems))
	return nil
}

func itemsField(list any) (reflect.Value, error) {
	v := reflect.ValueOf(list)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return reflect.Value{}, fmt.Errorf("paginated read: %T is not a pointer to a list", list)
	}
	field := v.Elem().FieldByName("Items")
	if !field.IsValid() || field.Kind() != reflect.Slice || !field.CanSet() {
		return reflect.Value{}, fmt.Errorf("paginated read: %T has no settable Items slice", list)
	}
	return field, nil
}
