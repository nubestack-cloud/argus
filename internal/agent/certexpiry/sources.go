package certexpiry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// certManagerGroup is the API group of cert-manager's Certificate kind.
const certManagerGroup = "cert-manager.io"

// FromCertManager maps a cert-manager Certificate to an Input. It reports
// false for anything that is not a cert-manager.io Certificate. A Certificate
// that has not been issued yet (or is in some renewal-failure states) has no
// status.notAfter; NotAfter stays nil and Aggregate rates it unknown.
func FromCertManager(u *unstructured.Unstructured) (Input, bool) {
	if u == nil {
		return Input{}, false
	}
	gvk := u.GroupVersionKind()
	if gvk.Group != certManagerGroup || gvk.Kind != "Certificate" {
		return Input{}, false
	}
	in := Input{
		Name:      u.GetName(),
		Namespace: u.GetNamespace(),
		Source:    SourceCertManager,
	}
	in.SecretName, _, _ = unstructured.NestedString(u.Object, "spec", "secretName")
	in.Issuer, _, _ = unstructured.NestedString(u.Object, "spec", "issuerRef", "name")
	if dns, ok, _ := unstructured.NestedSlice(u.Object, "spec", "dnsNames"); ok {
		for _, d := range dns {
			if ds, ok := d.(string); ok {
				in.Domains = append(in.Domains, ds)
			}
		}
	}
	if na, _, _ := unstructured.NestedString(u.Object, "status", "notAfter"); na != "" {
		if t, err := time.Parse(time.RFC3339, na); err == nil {
			in.NotAfter = &t
		}
	}
	if rt, _, _ := unstructured.NestedString(u.Object, "status", "renewalTime"); rt != "" {
		if t, err := time.Parse(time.RFC3339, rt); err == nil {
			in.RenewalTime = &t
		}
	}
	// PG5 (2026-10-13 parity review): the Ready condition's reason/message is
	// cert-manager's own stated cause ("DoesNotExist" the first time,
	// "Renewing" mid-cycle, a challenge/policy failure string once something
	// is actually wrong) — surfaced only when NOT True, since a healthy
	// Certificate's Ready=True condition has nothing to explain.
	for _, raw := range certManagerConditions(u) {
		if raw.condType == "Ready" && raw.status != "True" {
			in.ReadyReason, in.ReadyMessage = raw.reason, raw.message
			break
		}
	}
	return in, true
}

type certManagerCondition struct {
	condType, status, reason, message string
	lastTransitionTime                string
}

// certManagerConditions reads status.conditions the same shallow way every
// cert-manager-family kind (Certificate, CertificateRequest, Order,
// Challenge) exposes it — one shared reader rather than four, since the
// shape is identical across all four kinds this file and RequestChainFor
// below read.
func certManagerConditions(u *unstructured.Unstructured) []certManagerCondition {
	raw, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	out := make([]certManagerCondition, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		str := func(k string) string { s, _ := m[k].(string); return s }
		out = append(out, certManagerCondition{
			condType: str("type"), status: str("status"), reason: str("reason"), message: str("message"),
			lastTransitionTime: str("lastTransitionTime"),
		})
	}
	return out
}

func conditionOf(conds []certManagerCondition, condType string) (certManagerCondition, bool) {
	for _, c := range conds {
		if c.condType == condType {
			return c, true
		}
	}
	return certManagerCondition{}, false
}

// ownerUID returns the UID of child's controller owner, matching
// metav1.GetControllerOf's semantics against an unstructured object: the
// single ownerReference with controller:true, falling back to the first
// reference if none is explicitly marked (cert-manager always sets
// controller:true on these three kinds, but the fallback costs nothing and
// matches how this codebase's other owner-chain code treats a missing flag
// elsewhere).
func ownerUID(child *unstructured.Unstructured) (string, bool) {
	refs, _, _ := unstructured.NestedSlice(child.Object, "metadata", "ownerReferences")
	var fallback string
	for _, r := range refs {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		uid, _ := m["uid"].(string)
		if uid == "" {
			continue
		}
		if controller, _ := m["controller"].(bool); controller {
			return uid, true
		}
		if fallback == "" {
			fallback = uid
		}
	}
	return fallback, fallback != ""
}

// newestByCreation returns the object with the latest
// metadata.creationTimestamp among those whose controller owner UID is
// ownerUID — cert-manager retries by creating a NEW CertificateRequest/
// Order/Challenge rather than updating one in place, so "newest" is always
// "the current attempt."
func newestByCreation(objs []*unstructured.Unstructured, ownerUIDWanted string) *unstructured.Unstructured {
	var newest *unstructured.Unstructured
	var newestAt time.Time
	for _, o := range objs {
		uid, ok := ownerUID(o)
		if !ok || uid != ownerUIDWanted {
			continue
		}
		ts := o.GetCreationTimestamp().Time
		if newest == nil || ts.After(newestAt) {
			newest, newestAt = o, ts
		}
	}
	return newest
}

// RequestChainFor correlates a Certificate's newest renewal attempt three
// objects deep (PG5, 2026-10-13 parity review): the newest CertificateRequest
// it owns, the newest Order that request owns (ACME issuers only), and the
// newest Challenge that order owns. Matched purely by ownerReferences (never
// by name pattern), so this works the same for any issuer. Returns nil only
// when certObj itself owns no CertificateRequest yet — every other stage
// being absent (a non-ACME issuer never creates an Order; a request denied
// by policy never reaches one) is a normal, partial chain, not a nil result.
func RequestChainFor(certObj *unstructured.Unstructured, requests, orders, challenges []*unstructured.Unstructured) *RequestChain {
	req := newestByCreation(requests, string(certObj.GetUID()))
	if req == nil {
		return nil
	}
	chain := &RequestChain{RequestName: req.GetName()}
	reqConds := certManagerConditions(req)
	if ready, ok := conditionOf(reqConds, "Ready"); ok {
		chain.RequestReady = ready.status == "True"
		chain.RequestReason, chain.RequestMessage = ready.reason, ready.message
	}

	order := newestByCreation(orders, string(req.GetUID()))
	if order == nil {
		return chain
	}
	chain.OrderName = order.GetName()
	chain.OrderState, _, _ = unstructured.NestedString(order.Object, "status", "state")
	if ready, ok := conditionOf(certManagerConditions(order), "Ready"); ok {
		chain.OrderReason = ready.reason
	}

	challenge := newestByCreation(challenges, string(order.GetUID()))
	if challenge == nil {
		return chain
	}
	chain.ChallengeName = challenge.GetName()
	chain.ChallengeState, _, _ = unstructured.NestedString(challenge.Object, "status", "state")
	chain.ChallengeReason, _, _ = unstructured.NestedString(challenge.Object, "status", "reason")
	return chain
}

// ProbeServedCertificate opens a TLS connection to address (host:port) with
// the given SNI, reads the leaf certificate the server presents, and closes
// the connection. No HTTP request is sent and the chain is deliberately not
// verified: the point is to read the expiry of whatever is being served,
// including an expired or self-signed certificate that verification would
// reject. The returned Input has Source=served and Endpoint=address; callers
// fill Name/Namespace/SecretName from the Ingress or Gateway they probed.
func ProbeServedCertificate(ctx context.Context, address, sni string, timeout time.Duration) (Input, error) {
	if address == "" {
		return Input{}, errors.New("certexpiry: empty address")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: sni,
			// Reading an expired or untrusted certificate is the purpose of
			// the probe; nothing is sent over the connection.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return Input{}, fmt.Errorf("certexpiry: tls dial %s: %w", address, err)
	}
	defer conn.Close()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return Input{}, fmt.Errorf("certexpiry: %s: not a TLS connection", address)
	}
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return Input{}, fmt.Errorf("certexpiry: %s presented no certificate", address)
	}
	leaf := peers[0]
	notAfter := leaf.NotAfter.UTC()
	in := Input{
		Name:     sni,
		Issuer:   leaf.Issuer.CommonName,
		Subject:  leaf.Subject.CommonName,
		Domains:  append([]string(nil), leaf.DNSNames...),
		NotAfter: &notAfter,
		Source:   SourceServed,
		Endpoint: address,
	}
	if in.Issuer == "" {
		in.Issuer = leaf.Issuer.String()
	}
	if in.Subject == "" {
		in.Subject = leaf.Subject.String()
	}
	if in.Name == "" {
		in.Name = address
	}
	return in, nil
}
