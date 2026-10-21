package netpolmap

import (
	"fmt"
	"sort"
	"strings"
)

// findings derives the recommendations for one namespace's map. Each is a
// static, checkable fact about the policies as written; none is a guess about
// intent. Warnings are traffic that is probably open or broken by mistake;
// reviews may well be deliberate.
func findings(m Map, hasPolicies bool) []Finding {
	var out []Finding
	addItems := func(f Finding, items []string) {
		if len(items) == 0 {
			return
		}
		sort.Strings(items)
		if len(items) > MaxFindingItems {
			f.More = len(items) - MaxFindingItems
			items = items[:MaxFindingItems]
		}
		f.Objects = items
		out = append(out, f)
	}
	label := func(w Workload) string { return w.Kind + " " + w.Name }

	if !hasPolicies && len(m.Workloads) > 0 {
		var all []string
		for _, w := range m.Workloads {
			if !w.HostNetwork {
				all = append(all, label(w))
			}
		}
		addItems(Finding{
			Code: "no-policies", Severity: "review",
			Title: "No NetworkPolicy here: every pod accepts traffic from anywhere and can reach anywhere",
			Fix:   "Add a default-deny policy for the namespace, then allow what each workload needs",
		}, all)
		return out
	}

	var openIn, openOut, noDNS, openToAll, deadRule, halfOpen []string
	for _, w := range m.Workloads {
		if w.HostNetwork {
			continue // policy does not apply; nothing here is a finding
		}
		if !w.IngressIsolated {
			openIn = append(openIn, label(w))
		} else if !w.EgressIsolated {
			openOut = append(openOut, label(w))
		}
		if w.EgressIsolated && !allowsDNS(w.Egress) {
			noDNS = append(noDNS, label(w))
		}
		if w.IngressIsolated {
			for _, a := range w.Ingress {
				if a.Peer.Type == "anywhere" || (a.Peer.Type == "cidr" && isWholeInternet(a.Peer.CIDR)) {
					openToAll = append(openToAll, fmt.Sprintf("%s on %s (%s)", label(w), strings.Join(a.Ports, ", "), strings.Join(a.Policies, ", ")))
				}
			}
		}
		for _, side := range []struct {
			allows []Allow
			arrow  string
		}{{w.Ingress, "from"}, {w.Egress, "to"}} {
			for _, a := range side.allows {
				if a.Peer.Type == "none" {
					deadRule = append(deadRule, fmt.Sprintf("%s: %s %s (%s)", label(w), side.arrow, a.Peer.Selector, strings.Join(a.Policies, ", ")))
				}
				// A refused path is a finding only when the rule names this
				// workload alone. A broad selector (every pod of an app) that
				// happens to cover a workload whose own policy never sends this
				// traffic is the policies working as intended; the chip still
				// says "refused".
				if a.Effective == "blocked" && a.Peer.Matched == 1 {
					halfOpen = append(halfOpen, fmt.Sprintf("%s %s %s %s/%s on %s, refused by %s",
						label(w), side.arrow, a.Peer.Kind, a.Peer.Namespace, a.Peer.Name, strings.Join(a.Ports, ", "), strings.Join(a.BlockedBy, ", ")))
				}
			}
		}
	}
	var emptyPolicies []string
	for _, p := range m.Policies {
		if len(p.Workloads) == 0 {
			emptyPolicies = append(emptyPolicies, "NetworkPolicy "+p.Name)
		}
	}

	addItems(Finding{
		Code: "half-open", Severity: "warning",
		Title: "Allowed on one side, refused on the other: this traffic can never arrive",
		Fix:   "Add the matching rule on the refusing side, or remove the rule that allows it",
	}, halfOpen)
	addItems(Finding{
		Code: "dns-blocked", Severity: "warning",
		Title: "Outbound is restricted with no rule for DNS: name lookups will fail",
		Fix:   "Allow egress to kube-system on UDP and TCP 53",
	}, noDNS)
	addItems(Finding{
		Code: "open-ingress", Severity: "warning",
		Title: "Accepts traffic from anywhere: no policy restricts its inbound",
		Fix:   "Select these pods with a policy that lists who may connect",
	}, openIn)
	addItems(Finding{
		Code: "open-to-all", Severity: "warning",
		Title: "A rule admits every source, including outside the cluster",
		Fix:   "Narrow the rule to the namespaces, pods or address ranges that need it",
	}, openToAll)
	addItems(Finding{
		Code: "egress-open", Severity: "review",
		Title: "Inbound is restricted but outbound is not",
		Fix:   "Add Egress to a policy selecting these pods if they should only reach known destinations",
	}, openOut)
	addItems(Finding{
		Code: "dead-rule", Severity: "review",
		Title: "A rule's selector matches nothing right now",
		Fix:   "Check the labels: a renamed workload or namespace leaves the rule admitting nobody",
	}, deadRule)
	addItems(Finding{
		Code: "empty-policy", Severity: "review",
		Title: "A policy selects no running pods",
		Fix:   "Remove it, or fix its podSelector",
	}, emptyPolicies)
	if out == nil {
		out = []Finding{}
	}
	return out
}

// allowsDNS reports whether some egress rule admits port 53 (any protocol),
// or all ports, to any peer. A rule naming a resolver by address counts: the
// check is "is there a way to resolve names", not "is it kube-dns".
func allowsDNS(egress []Allow) bool {
	for _, a := range egress {
		if a.Peer.Type == "none" {
			continue
		}
		for _, p := range a.Ports {
			if p == "all ports" || strings.HasSuffix(p, " all") || strings.HasSuffix(p, " 53") || portRangeHas(p, 53) {
				return true
			}
		}
	}
	return false
}

func portRangeHas(label string, n int) bool {
	parts := strings.SplitN(label, " ", 2)
	if len(parts) != 2 {
		return false
	}
	var lo, hi int
	if _, err := fmt.Sscanf(parts[1], "%d-%d", &lo, &hi); err != nil {
		return false
	}
	return lo <= n && n <= hi
}

func isWholeInternet(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}
