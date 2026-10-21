package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sourceOf is the AllowlistSource a test wires into a Policy: entries are
// parsed through the real ParseAllowlist, so a test can never assert
// behaviour for a list the product would have refused to store.
func sourceOf(t *testing.T, entries ...AllowlistEntry) AllowlistSource {
	t.Helper()
	al, err := ParseAllowlist(entries)
	if err != nil {
		t.Fatalf("ParseAllowlist(%v): %v", entries, err)
	}
	return func(context.Context) (Allowlist, error) { return al, nil }
}

// withLookup substitutes the package resolver for the duration of one test.
// This is the only way to prove what happens when a name resolves to a cloud
// metadata address without owning DNS.
func withLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IP, error)) {
	t.Helper()
	prev := lookupIP
	lookupIP = fn
	t.Cleanup(func() { lookupIP = prev })
}

// --- The four properties the allowlist has to have -------------------------

// TestAllowlist_PrivateNotListedIsStillRefused is the default the whole
// feature rests on: adding an allowlist does not make private destinations
// reachable, it makes the ones an operator NAMED reachable.
func TestAllowlist_PrivateNotListedIsStillRefused(t *testing.T) {
	c := NewClient(Policy{
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "10.20.0.0/16", Reason: "self-hosted vLLM subnet"}),
	}, 2*time.Second)

	_, err := c.Get("http://10.99.0.1/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected a private address outside the allowlist to stay refused, got: %v", err)
	}
	// Property 5 of the task: the refusal has to tell an operator which
	// lever exists, not just that it failed.
	if !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("expected the refusal to name the allowlist as the lever, got: %v", err)
	}
}

// TestAllowlist_ListedPrivateDestinationConnects is the other half: a named
// destination is actually reachable, or the feature does nothing.
func TestAllowlist_ListedPrivateDestinationConnects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(Policy{
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "127.0.0.1/32", Reason: "test server"}),
	}, 2*time.Second)

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected an allowlisted loopback destination to be reachable, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestAllowlist_HostEntryMatchesTheResolvedAddress pins the semantics chosen
// for a hostname entry: it is resolved by the guard and permits the addresses
// it resolves to. Here "svc.internal.test" resolves to the loopback address
// the test server is on, and the request is made to that address by a
// DIFFERENT name — which must still be permitted, because the allowlist
// names addresses, not names.
func TestAllowlist_HostEntryMatchesTheResolvedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withLookup(t, func(ctx context.Context, host string) ([]net.IP, error) {
		switch host {
		case "svc.internal.test", "other.internal.test":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		default:
			return nil, errors.New("no such host")
		}
	})

	c := NewClient(Policy{
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "svc.internal.test", Reason: "internal GHES"}),
	}, 2*time.Second)

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	resp, err := c.Get("http://other.internal.test:" + port + "/")
	if err != nil {
		t.Fatalf("expected the allowlist to permit the resolved address regardless of the requested name, got: %v", err)
	}
	resp.Body.Close()
}

// TestAllowlist_MetadataCannotBeAllowlisted is the single most important
// property here, checked at every layer it could be broken at.
func TestAllowlist_MetadataCannotBeAllowlisted(t *testing.T) {
	// 1. Storing one is a parse error, in all three spellings.
	for _, dest := range []string{
		"169.254.169.254",
		"fd00:ec2::254",
		"169.254.0.0/16",
		"169.254.169.0/24",
		"metadata.google.internal",
		"metadata",
		"METADATA.GOOGLE.INTERNAL.",
	} {
		if _, err := ParseAllowlist([]AllowlistEntry{{Destination: dest, Reason: "operator insists"}}); err == nil {
			t.Fatalf("expected %q to be rejected as an allowlist entry, it was accepted", dest)
		}
	}

	// 2. A hostname entry whose DNS answer is a metadata address permits
	// nothing — this is the form that could slip past parse-time validation,
	// because what it resolves to is not knowable when it is stored.
	withLookup(t, func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	})
	c := NewClient(Policy{
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "vllm.internal.test", Reason: "self-hosted model"}),
	}, 2*time.Second)

	// Reached by the allowlisted name itself...
	_, err := c.Get("http://vllm.internal.test/latest/meta-data/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected a name resolving to the metadata address to be refused despite being allowlisted, got: %v", err)
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("expected the refusal to state the metadata reason, got: %v", err)
	}

	// ...and by the literal address, with that same entry in place.
	_, err = c.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected the metadata address to be refused with an allowlist configured, got: %v", err)
	}

	// 3. The matcher itself says no, even handed a metadata address
	// directly with a list that (hypothetically) contained one.
	al := Allowlist{entries: []parsedEntry{{destination: "169.254.169.254", reason: "smuggled past validation", ip: net.ParseIP("169.254.169.254")}}}
	if _, ok := al.permits(context.Background(), net.ParseIP("169.254.169.254")); ok {
		t.Fatal("Allowlist.permits matched a cloud metadata address — the last line of defence failed")
	}
}

// TestAllowlist_RedirectFromAllowedToAnotherPrivateAddressIsRefused proves
// the allowlist did not reopen the redirect hole: reaching an allowed
// destination does not make whatever it points at next reachable.
func TestAllowlist_RedirectFromAllowedToAnotherPrivateAddressIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.1.2.3/internal", http.StatusFound)
	}))
	defer srv.Close()

	c := NewClient(Policy{
		// The server itself IS allowlisted; the redirect target is not.
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "127.0.0.1/32", Reason: "test server"}),
	}, 2*time.Second)

	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected the redirect to a private address outside the allowlist to be refused")
	}
	if !strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("expected the refusal to name the redirect target, got: %v", err)
	}
}

// TestAllowlist_RedirectFromAllowedToMetadataIsRefused is the same shape as
// the test above with the target that matters most.
func TestAllowlist_RedirectFromAllowedToMetadataIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	c := NewClient(Policy{
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "127.0.0.0/8", Reason: "test server"}),
	}, 2*time.Second)

	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("expected a redirect to the metadata address to be refused from an allowlisted origin")
	}
}

// --- Parse-time validation -------------------------------------------------

func TestParseAllowlist_RejectsEntriesThatWouldWidenBeyondPrivateRanges(t *testing.T) {
	for _, dest := range []string{
		"0.0.0.0/0",     // the "turn it off" spelling
		"::/0",          // ...and its IPv6 twin
		"8.8.8.8",       // a public address needs no entry
		"0.0.0.0/1",     // spans public space
		"128.0.0.0/1",   // ditto
		"10.0.0.0/7",    // wider than RFC1918's own block
		"192.168.1.5/8", // host bits set
	} {
		if _, err := ParseAllowlist([]AllowlistEntry{{Destination: dest, Reason: "because"}}); err == nil {
			t.Fatalf("expected %q to be rejected, it was accepted", dest)
		}
	}
}

func TestParseAllowlist_AcceptsRealPrivateDestinations(t *testing.T) {
	for _, dest := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.10.0/24",
		"127.0.0.1",
		"10.20.0.5",
		// Narrower than fc00::/7 or fd00::/8 on purpose: both of those
		// contain AWS's IPv6 metadata address fd00:ec2::254 and are
		// therefore refused — see the metadata test.
		"fd00:1234::/32",
		"ghe.internal.example.com",
		"vllm",
	} {
		if _, err := ParseAllowlist([]AllowlistEntry{{Destination: dest, Reason: "because"}}); err != nil {
			t.Fatalf("expected %q to be accepted, got: %v", dest, err)
		}
	}
}

func TestParseAllowlist_RequiresAReasonPerEntry(t *testing.T) {
	_, err := ParseAllowlist([]AllowlistEntry{{Destination: "10.0.0.1"}})
	if err == nil {
		t.Fatal("expected an entry with no reason to be rejected")
	}
	if !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected the error to name the missing reason, got: %v", err)
	}
	if _, err := ParseAllowlist([]AllowlistEntry{{Destination: "10.0.0.1", Reason: "   "}}); err == nil {
		t.Fatal("expected a whitespace-only reason to be rejected")
	}
}

func TestParseAllowlist_RejectsDuplicatesURLsAndOversizedLists(t *testing.T) {
	if _, err := ParseAllowlist([]AllowlistEntry{
		{Destination: "10.0.0.1", Reason: "a"},
		{Destination: "10.0.0.1", Reason: "b"},
	}); err == nil {
		t.Fatal("expected a duplicate destination to be rejected")
	}
	for _, dest := range []string{
		"https://ghe.internal.example.com",
		"ghe.internal.example.com:8443",
		"ghe.internal.example.com/api/v3",
		"user@ghe.internal.example.com",
		"ghe internal",
	} {
		if _, err := ParseAllowlist([]AllowlistEntry{{Destination: dest, Reason: "because"}}); err == nil {
			t.Fatalf("expected %q (not a bare hostname) to be rejected", dest)
		}
	}
	tooMany := make([]AllowlistEntry, maxAllowlistEntries+1)
	for i := range tooMany {
		tooMany[i] = AllowlistEntry{Destination: net.IPv4(10, 0, byte(i/256), byte(i%256)).String(), Reason: "bulk"}
	}
	if _, err := ParseAllowlist(tooMany); err == nil {
		t.Fatalf("expected more than %d entries to be rejected", maxAllowlistEntries)
	}
}

// --- Failing closed --------------------------------------------------------

// TestAllowlist_SourceErrorRefusesRatherThanAllows: a guard that opens when
// it cannot read its own policy is not a guard.
func TestAllowlist_SourceErrorRefusesRatherThanAllows(t *testing.T) {
	c := NewClient(Policy{
		PrivateDestinations: func(context.Context) (Allowlist, error) {
			return Allowlist{}, errors.New("database is down")
		},
	}, 2*time.Second)

	_, err := c.Get("http://10.1.2.3/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected a refusal when the allowlist cannot be read, got: %v", err)
	}
	if !strings.Contains(err.Error(), "database is down") {
		t.Fatalf("expected the refusal to carry the read failure, got: %v", err)
	}
}

// TestNewClient_PanicsWhenBothAllowancesAreSet locks the one combination
// that would make an operator's allowlist dead configuration while the
// settings screen still showed it as the thing granting access.
func TestNewClient_PanicsWhenBothAllowancesAreSet(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic when AllowPrivate and PrivateDestinations are both set")
		}
	}()
	NewClient(Policy{
		AllowPrivate:        true,
		Reason:              "test",
		PrivateDestinations: sourceOf(t, AllowlistEntry{Destination: "10.0.0.1", Reason: "test"}),
	}, time.Second)
}

// TestAllowlist_NoSourceMeansTheOldRefusalWording keeps the refusal honest
// for any caller with no allowlist source: telling its operator to "add it to
// the allowlist" would be advice for a control that client does not consult.
// (internal/notify, internal/idp and internal/knowledge never reach this
// branch at all — each holds a wholesale AllowPrivate — but a future
// default-deny caller that is given no source would, and it must not be
// pointed at a lever it does not have.)
func TestAllowlist_NoSourceMeansTheOldRefusalWording(t *testing.T) {
	c := NewClient(Policy{}, 2*time.Second)
	_, err := c.Get("http://10.1.2.3/")
	if err == nil || !IsRefusal(err) {
		t.Fatalf("expected a refusal, got: %v", err)
	}
	if strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("a policy with no allowlist source must not advertise the allowlist, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not allow private destinations") {
		t.Fatalf("expected the original refusal wording, got: %v", err)
	}
}

// TestParseAllowlist_RejectsUniqueLocalBlocksContainingIPv6Metadata records a
// consequence an operator will meet: fc00::/7 and fd00::/8 are legitimate
// unique-local ranges, and both contain AWS's IPv6 metadata address, so
// neither can be allowlisted wholesale. The narrower prefix an operator
// actually runs on is accepted.
func TestParseAllowlist_RejectsUniqueLocalBlocksContainingIPv6Metadata(t *testing.T) {
	for _, dest := range []string{"fc00::/7", "fd00::/8", "fd00:ec2::/32"} {
		if _, err := ParseAllowlist([]AllowlistEntry{{Destination: dest, Reason: "because"}}); err == nil {
			t.Fatalf("expected %q to be rejected for containing fd00:ec2::254", dest)
		}
	}
	if _, err := ParseAllowlist([]AllowlistEntry{{Destination: "fd00:1234::/32", Reason: "because"}}); err != nil {
		t.Fatalf("expected a unique-local prefix clear of the metadata address to be accepted, got: %v", err)
	}
}
