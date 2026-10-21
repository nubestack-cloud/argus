package outbound

// The operator allowlist of specific private destinations.
//
// # Why this exists, and what was deliberately NOT built
//
// Policy.AllowPrivate (outbound.go) is a compile-time, per-caller,
// all-or-nothing decision: a Go literal at a construction site, never read
// from config. That is exactly right for internal/idp, internal/knowledge
// and internal/notify, whose destinations are private BY DESIGN (a Dex
// broker on localhost, an Ollama server on the LAN, an internal chat
// receiver), and exactly wrong for the two boundaries this file serves — the AI provider's base_url (B5) and
// a repository's API base URL (B7). Those two are normally public
// (api.openai.com, api.github.com) and occasionally private (a self-hosted
// vLLM, an internal GitHub Enterprise Server), and which one a given
// installation has is an operator fact, not a code fact.
//
// The owner's decision (2026-09-19), recorded so a future reader does not
// re-open it: keep default-deny, and add an explicit operator opt-in that
// names SPECIFIC destinations. Both alternatives were considered and
// REJECTED — allowing private destinations by default, and shipping no
// opt-in at all. So this is deliberately not a boolean. A settings-backed
// "allowPrivate: true" would be the rejected option one config step away:
// one click and every private address in the deployment is reachable by an
// admin-supplied URL again. An operator here names addresses; everything
// not named stays refused, and every exception is visible in configuration
// with its own written justification.
//
// # Four properties this file is responsible for
//
//  1. An entry can only ever permit an address that would OTHERWISE BE
//     REFUSED. ParseAllowlist rejects any IP or CIDR that is not wholly
//     inside a loopback/link-local/RFC1918/RFC4193 block, so "0.0.0.0/0" is
//     not a spelling of "turn the guard off" — it is a parse error. There
//     is no entry shape that widens anything beyond the private ranges.
//
//  2. Cloud metadata is never reachable, by any entry, by any route. Three
//     independent checks: ParseAllowlist refuses a metadata IP literal, a
//     metadata hostname and any CIDR that CONTAINS a metadata address;
//     Allowlist.permits refuses to match a metadata IP even if one somehow
//     got stored; and classify (outbound.go) refuses metadata BEFORE the
//     allowlist is consulted at all. Removing any one of the three still
//     leaves the address refused.
//
//  3. The allowlist is matched against the RESOLVED IP, at dial time,
//     inside DialContext — never against the hostname string in the URL.
//     That is what keeps the DNS-rebinding defence (SR-9) honest: the
//     address that is checked is the exact address that is then dialled.
//     A hostname ENTRY is therefore not a string match either; see
//     parsedEntry.host below for what it actually means.
//
//  4. Every entry carries its own Reason, required and non-empty, for the
//     same purpose Policy.Reason serves for the compile-time allowance: an
//     exception that cannot state why it exists is one no future reader can
//     evaluate.

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// maxAllowlistEntries bounds the list. Not a storage concern — a bound on
// work done inside a dial: a hostname entry costs a DNS lookup each time
// the allowlist is consulted (see parsedEntry.host), so an unbounded list
// would let a settings write turn every refused-private dial into hundreds
// of resolver round-trips. 64 is far above any plausible real deployment
// (an operator naming more than a handful of private destinations should be
// naming a CIDR instead).
const maxAllowlistEntries = 64

// AllowlistEntry is one operator-named private destination, exactly as it
// is stored and displayed.
type AllowlistEntry struct {
	// Destination is an IP literal ("10.20.0.5"), a CIDR ("10.20.0.0/16")
	// or a hostname ("vllm.internal.example.com"). See parsedEntry for what
	// each form means at match time — in particular, a hostname is NOT
	// matched against the request's hostname.
	Destination string
	// Reason is the operator's written justification, required. This is
	// Policy.Reason's contract carried down to a single entry: NewClient
	// panics on an AllowPrivate with no Reason, and ParseAllowlist errors
	// on an entry with no Reason, for the same reason in both cases.
	Reason string
}

// Allowlist is a parsed, validated, immutable set of AllowlistEntry. The
// zero value is a valid empty allowlist that permits nothing, which is the
// correct behaviour for every caller that has not been given one.
type Allowlist struct {
	entries []parsedEntry
}

// parsedEntry is one entry with its form already decided. Exactly one of
// ip/cidr/host is set.
type parsedEntry struct {
	destination string
	reason      string

	ip   net.IP
	cidr *net.IPNet
	// host is a hostname entry, and its semantics are the subtle part of
	// this file.
	//
	// It is NOT compared against the hostname in the URL being dialled.
	// Matching on the requested hostname, before or instead of resolution,
	// is precisely the hole internal/outbound's DialContext exists to
	// close: a name that resolves to an allowed address when it is checked
	// and to a different one when it is dialled. An allowlist keyed on the
	// name string would hand that hole straight back.
	//
	// What it means instead: the guard resolves THIS name itself, at dial
	// time, and the entry permits exactly the addresses that resolution
	// returns. The question asked is always the same one — "is the address
	// I am about to connect to an address the operator named?" — and a
	// hostname is only a late-bound way of naming addresses.
	//
	// The consequence, stated plainly because it is a real trade and not a
	// detail: a hostname entry inherits its trust from DNS, so an operator
	// who can control the A record can change what the entry permits. A
	// CIDR or IP entry cannot be moved that way and is the form to prefer.
	// What a hostname entry can never do is widen the set of ADDRESS
	// CLASSES that are reachable: permits refuses a metadata IP whatever
	// DNS says, and classify only consults the allowlist for addresses that
	// are already private and already refused.
	host string
}

func (e parsedEntry) public() AllowlistEntry {
	return AllowlistEntry{Destination: e.destination, Reason: e.reason}
}

// AllowlistSource is how a client that was built once, at hub startup,
// reads an allowlist that an operator edits at runtime. It is called during
// DialContext, and only for an address that is about to be refused, so the
// common public-destination path never pays for it.
//
// A source returning an error does NOT fall back to "allow": classify turns
// it into a refusal that names the read failure, because a guard that opens
// when it cannot read its own policy is not a guard.
type AllowlistSource func(ctx context.Context) (Allowlist, error)

// allowlistableBlocks is the complete set of ranges an entry may name: the
// ranges classify refuses by default. An entry outside them is refused at
// parse time, which is what makes it impossible to express "allow
// everything" as an allowlist entry (see this file's property 1).
//
// These mirror net.IP.IsLoopback / IsLinkLocalUnicast / IsPrivate exactly.
// Link-local multicast (224.0.0.0/24, ff02::/16) is deliberately absent:
// classify refuses it, and nothing in this product dials a multicast
// address, so there is no legitimate entry to accommodate.
var allowlistableBlocks = mustParseCIDRs(
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local (metadata addresses inside it are refused separately)
	"fc00::/7",       // RFC4193 unique-local
	"::1/128",        // IPv6 loopback
	"fe80::/10",      // IPv6 link-local
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("outbound: bad built-in CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// ParseAllowlist validates and parses operator-supplied entries. It returns
// an error describing the FIRST problem it finds, phrased for an operator
// reading it in an API response — these strings reach a 400.
//
// It is the single validation point: internal/api calls it to reject a bad
// PUT, internal/settings.Update calls it again before writing (the handler
// is one caller, not a gate), and the dial path parses whatever was stored.
// A row hand-edited in psql past the first two is still re-validated by the
// third.
func ParseAllowlist(in []AllowlistEntry) (Allowlist, error) {
	if len(in) > maxAllowlistEntries {
		return Allowlist{}, fmt.Errorf("outbound: at most %d allowlisted private destinations are permitted, got %d", maxAllowlistEntries, len(in))
	}
	seen := make(map[string]bool, len(in))
	out := make([]parsedEntry, 0, len(in))
	for _, raw := range in {
		dest := strings.TrimSpace(raw.Destination)
		reason := strings.TrimSpace(raw.Reason)
		if dest == "" {
			return Allowlist{}, fmt.Errorf("outbound: an allowlisted private destination cannot be empty")
		}
		if reason == "" {
			// Same rule, and the same reason, as NewClient's panic on an
			// AllowPrivate policy with no Reason.
			return Allowlist{}, fmt.Errorf("outbound: allowlisted private destination %q needs a reason — an exception that does not say why it exists cannot be reviewed later", dest)
		}
		key := strings.ToLower(dest)
		if seen[key] {
			return Allowlist{}, fmt.Errorf("outbound: duplicate allowlisted private destination %q", dest)
		}
		seen[key] = true

		e, err := parseEntry(dest, reason)
		if err != nil {
			return Allowlist{}, err
		}
		out = append(out, e)
	}
	return Allowlist{entries: out}, nil
}

func parseEntry(dest, reason string) (parsedEntry, error) {
	e := parsedEntry{destination: dest, reason: reason}

	switch {
	case strings.Contains(dest, "/"):
		ip, n, err := net.ParseCIDR(dest)
		if err != nil {
			return parsedEntry{}, fmt.Errorf("outbound: %q is not a valid CIDR: %v", dest, err)
		}
		if !ip.Equal(n.IP) {
			return parsedEntry{}, fmt.Errorf("outbound: %q has host bits set — write the network address (%s)", dest, n.String())
		}
		// Property 2: no entry may reach a metadata address, and a CIDR is
		// the form most likely to do it by accident (169.254.0.0/16 looks
		// like an ordinary link-local range and contains 169.254.169.254).
		for _, m := range metadataIPs {
			if m != nil && n.Contains(m) {
				return parsedEntry{}, fmt.Errorf("outbound: %q contains the cloud metadata address %s, which is refused unconditionally and cannot be allowlisted — name the specific addresses you need instead", dest, m)
			}
		}
		// Property 1: an entry may only name addresses that are otherwise
		// refused, so the allowlist cannot be spelled as a blanket allow.
		if !withinAllowlistableBlock(n) {
			return parsedEntry{}, fmt.Errorf("outbound: %q is not wholly inside a private, loopback or link-local range — this allowlist only permits destinations that would otherwise be refused, so it cannot be used to widen access to public addresses", dest)
		}
		e.cidr = n
		return e, nil

	case net.ParseIP(dest) != nil:
		ip := net.ParseIP(dest)
		if isMetadataIP(ip) {
			return parsedEntry{}, fmt.Errorf("outbound: %q is a cloud metadata address — refused unconditionally, no allowance exists for this and none can be configured", dest)
		}
		if !isAllowlistableIP(ip) {
			return parsedEntry{}, fmt.Errorf("outbound: %q is not a private, loopback or link-local address — this allowlist only permits destinations that would otherwise be refused, and a public address needs no entry", dest)
		}
		e.ip = ip
		return e, nil

	default:
		host, err := normalizeAllowlistHost(dest)
		if err != nil {
			return parsedEntry{}, err
		}
		e.host = host
		return e, nil
	}
}

// normalizeAllowlistHost lowercases, trims a trailing dot, and rejects
// anything that is not a bare hostname. A scheme, a path, a port or an
// embedded credential here means the operator pasted a URL, and silently
// accepting the first component of one would allowlist something other than
// what they read back on the screen.
func normalizeAllowlistHost(dest string) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(dest, "."))
	if isMetadataHost(h) {
		return "", fmt.Errorf("outbound: %q is a cloud metadata hostname — refused unconditionally, no allowance exists for this and none can be configured", dest)
	}
	if strings.ContainsAny(h, "/\\@: \t") {
		return "", fmt.Errorf("outbound: %q is not a bare hostname — enter just the host (no scheme, port, path or credential), an IP address, or a CIDR", dest)
	}
	if h == "" {
		return "", fmt.Errorf("outbound: an allowlisted private destination cannot be empty")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return "", fmt.Errorf("outbound: %q is not a valid hostname", dest)
		}
	}
	return h, nil
}

func isAllowlistableIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// withinAllowlistableBlock reports whether every address in n is inside one
// of allowlistableBlocks. Checked as a subnet relation rather than by
// testing the first and last address, because only containment in a single
// block proves nothing in between escapes.
func withinAllowlistableBlock(n *net.IPNet) bool {
	subOnes, subBits := n.Mask.Size()
	for _, block := range allowlistableBlocks {
		supOnes, supBits := block.Mask.Size()
		if subBits != supBits {
			continue // different address family
		}
		if supOnes <= subOnes && block.Contains(n.IP) {
			return true
		}
	}
	return false
}

// Empty reports whether this allowlist names nothing.
func (a Allowlist) Empty() bool { return len(a.entries) == 0 }

// Entries returns the entries as stored, for display and audit. The
// returned slice is a copy.
func (a Allowlist) Entries() []AllowlistEntry {
	out := make([]AllowlistEntry, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, e.public())
	}
	return out
}

// permits reports whether ip is named by this allowlist, and which entry
// named it.
//
// ip is always an address that has ALREADY been resolved and already
// classified as private by classify — this function never sees a hostname
// and never decides anything about a public address. The metadata check at
// the top is redundant with classify's own unconditional refusal and with
// ParseAllowlist's; it is here anyway because this is the function that
// says "yes", and the one place a "yes" must be impossible is a metadata
// address.
func (a Allowlist) permits(ctx context.Context, ip net.IP) (AllowlistEntry, bool) {
	if len(a.entries) == 0 || ip == nil {
		return AllowlistEntry{}, false
	}
	if isMetadataIP(ip) {
		return AllowlistEntry{}, false
	}
	for _, e := range a.entries {
		switch {
		case e.ip != nil:
			if e.ip.Equal(ip) {
				return e.public(), true
			}
		case e.cidr != nil:
			if e.cidr.Contains(ip) {
				return e.public(), true
			}
		case e.host != "":
			// Resolved here, at dial time, by the guard itself — see the
			// host field's doc comment for why this is a resolution and not
			// a string comparison against the request's hostname.
			addrs, err := lookupIP(ctx, e.host)
			if err != nil {
				continue
			}
			for _, candidate := range addrs {
				if isMetadataIP(candidate) {
					continue
				}
				if candidate.Equal(ip) {
					return e.public(), true
				}
			}
		}
	}
	return AllowlistEntry{}, false
}
