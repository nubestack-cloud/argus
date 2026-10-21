package remediation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testContent() PlanContent {
	return PlanContent{
		RecommendationID: "rec_abc123",
		ActionType:       ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "checkout",
		Params:           []byte(`{"replicas":4}`),
	}
}

func TestPlanHashDeterministic(t *testing.T) {
	content := testContent()
	h1, err := planHash(content)
	if err != nil {
		t.Fatalf("planHash: %v", err)
	}
	h2, err := planHash(content)
	if err != nil {
		t.Fatalf("planHash: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("planHash is not deterministic: %q != %q", h1, h2)
	}

	changed := content
	changed.TargetName = "other"
	h3, err := planHash(changed)
	if err != nil {
		t.Fatalf("planHash: %v", err)
	}
	if h1 == h3 {
		t.Fatalf("planHash did not change when content changed")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)

	signed, err := Sign(testContent(), "clu_1", expiresAt, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(signed, "clu_1", key, now); err != nil {
		t.Fatalf("Verify of a freshly signed plan failed: %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)

	signed, err := Sign(testContent(), "clu_1", expiresAt, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	afterExpiry := expiresAt.Add(time.Second)
	if err := Verify(signed, "clu_1", key, afterExpiry); err == nil {
		t.Fatalf("Verify accepted a plan past its expiresAt")
	}
}

func TestVerifyRejectsWrongCluster(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := Sign(testContent(), "clu_1", now.Add(time.Minute), key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(signed, "clu_2", key, now); err == nil {
		t.Fatalf("Verify accepted a plan addressed to a different cluster")
	}
}

func TestVerifyRejectsTamperedField(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := Sign(testContent(), "clu_1", now.Add(time.Minute), key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := signed
	tampered.Params = []byte(`{"replicas":9999}`)
	if err := Verify(tampered, "clu_1", key, now); err == nil {
		t.Fatalf("Verify accepted a plan whose params were tampered with after signing")
	}

	tamperedTarget := signed
	tamperedTarget.TargetName = "some-other-deployment"
	if err := Verify(tamperedTarget, "clu_1", key, now); err == nil {
		t.Fatalf("Verify accepted a plan whose target was tampered with after signing")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	wrongKey := []byte("a-different-32-byte-test-key!!!!")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := Sign(testContent(), "clu_1", now.Add(time.Minute), key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(signed, "clu_1", wrongKey, now); err == nil {
		t.Fatalf("Verify accepted a signature made with a different key")
	}
}

func TestDeriveClusterSigningKeyIsPerCluster(t *testing.T) {
	root := []byte("a-32-byte-root-signing-test-key!")

	k1, err := DeriveClusterSigningKey(root, "clu_1")
	if err != nil {
		t.Fatalf("DeriveClusterSigningKey: %v", err)
	}
	k1Again, err := DeriveClusterSigningKey(root, "clu_1")
	if err != nil {
		t.Fatalf("DeriveClusterSigningKey: %v", err)
	}
	if string(k1) != string(k1Again) {
		t.Fatalf("DeriveClusterSigningKey is not deterministic for the same cluster")
	}

	k2, err := DeriveClusterSigningKey(root, "clu_2")
	if err != nil {
		t.Fatalf("DeriveClusterSigningKey: %v", err)
	}
	if string(k1) == string(k2) {
		t.Fatalf("DeriveClusterSigningKey produced the same key for two different clusters")
	}
	if len(k1) != 32 {
		t.Fatalf("expected a 32-byte derived key, got %d bytes", len(k1))
	}
}

// PlanContent.DryRun claims `omitempty` keeps every pre-existing plan's
// signature byte-identical. That is a compatibility promise about agents
// already deployed in customers' clusters — an agent holding a key derived
// before this field existed must still verify plans signed after it. A claim
// like that belongs in a test, not only in a comment.
func TestDryRunFalseDoesNotChangeAnExistingPlansSignature(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	expiry := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	content := PlanContent{
		RecommendationID: "plan_1",
		ActionType:       ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           json.RawMessage(`{"replicas":4}`),
		ResourceVersion:  "100",
	}

	// The signature this exact content produced before the field existed,
	// recomputed from the marshaled form an omitempty field must not appear
	// in. If DryRun ever loses its omitempty, or is reordered into the
	// marshaled output some other way, these diverge.
	marshaled, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(marshaled), "dryRun") {
		t.Errorf("a plan with DryRun unset marshals it anyway, which changes every existing signature: %s", marshaled)
	}

	explicitFalse := content
	explicitFalse.DryRun = false
	a, err := Sign(content, "clu_1", expiry, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := Sign(explicitFalse, "clu_1", expiry, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if a.Signature != b.Signature {
		t.Error("setting DryRun to its zero value changed the signature")
	}

	// And the inverse, which is the security half: true must NOT verify
	// against a signature made for false.
	dry := content
	dry.DryRun = true
	forged := a
	forged.DryRun = true
	if err := Verify(forged, "clu_1", key, expiry.Add(-time.Minute)); err == nil {
		t.Error("flipping DryRun to true on a signed real plan still verified — the flag is outside the signature")
	}
}
