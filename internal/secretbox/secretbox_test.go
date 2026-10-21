package secretbox

import (
	"strings"
	"testing"
)

func newTestKeeper(t *testing.T) *Keeper {
	t.Helper()
	kek, err := GenerateLocalKEK()
	if err != nil {
		t.Fatalf("GenerateLocalKEK: %v", err)
	}
	k, err := NewLocalKeeper(kek)
	if err != nil {
		t.Fatalf("NewLocalKeeper: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newTestKeeper(t)
	secret := []byte("github_pat_11ABCDEFG_notarealtoken")

	sealed, version, err := k.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if version != KeyVersionLocalV1 {
		t.Errorf("key version = %q, want %q", version, KeyVersionLocalV1)
	}
	// The whole point: the stored form must not contain the secret.
	if strings.Contains(sealed, "github_pat") || strings.Contains(sealed, string(secret)) {
		t.Fatalf("the sealed form leaks the plaintext: %s", sealed)
	}

	out, err := k.Open(sealed, version)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(out) != string(secret) {
		t.Errorf("round trip = %q, want %q", out, secret)
	}
}

// A fresh DEK per secret is what makes the envelope an envelope. Without it,
// two identical secrets would seal identically and a KEK rotation would have to
// re-encrypt every payload rather than re-wrap keys.
func TestEachSealUsesAFreshDEK(t *testing.T) {
	k := newTestKeeper(t)
	a, _, err := k.Seal([]byte("same secret"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := k.Seal([]byte("same secret"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("sealing the same plaintext twice produced identical ciphertext — the DEK or nonce is being reused")
	}
	// Both must still open, which is what distinguishes "fresh key" from
	// "broken".
	for i, c := range []string{a, b} {
		out, err := k.Open(c, KeyVersionLocalV1)
		if err != nil || string(out) != "same secret" {
			t.Errorf("ciphertext %d did not open: %v", i, err)
		}
	}
}

// GCM was chosen so a tampered stored value fails loudly instead of decrypting
// to garbage a caller might use as a live credential.
func TestTamperingIsDetected(t *testing.T) {
	k := newTestKeeper(t)
	sealed, _, err := k.Seal([]byte("a-real-token"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sealed, ".")

	// Flip a character in the payload.
	body := []byte(parts[2])
	body[len(body)/2] ^= 'A' ^ 'B'
	if _, err := k.Open(strings.Join([]string{parts[0], parts[1], string(body)}, "."), KeyVersionLocalV1); err == nil {
		t.Error("a tampered payload opened successfully")
	}

	// Flip a character in the wrapped DEK.
	dek := []byte(parts[1])
	dek[len(dek)/2] ^= 'A' ^ 'B'
	if _, err := k.Open(strings.Join([]string{parts[0], string(dek), parts[2]}, "."), KeyVersionLocalV1); err == nil {
		t.Error("a tampered wrapped DEK opened successfully")
	}
}

func TestAnotherKEKCannotOpenIt(t *testing.T) {
	sealed, _, err := newTestKeeper(t).Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestKeeper(t).Open(sealed, KeyVersionLocalV1); err == nil {
		t.Fatal("a different KEK opened the secret")
	}
}

// A row written by a KEK this build does not hold must say so, not report an
// authentication failure — which would read as data corruption and send someone
// looking for the wrong problem.
func TestUnknownKeyVersionIsRefusedByName(t *testing.T) {
	k := newTestKeeper(t)
	sealed, _, err := k.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Open(sealed, "kms-v1")
	if err == nil {
		t.Fatal("a secret sealed under an unknown key version was accepted")
	}
	if !strings.Contains(err.Error(), "kms-v1") || !strings.Contains(err.Error(), "key version") {
		t.Errorf("error does not name the key version mismatch: %v", err)
	}
}

// An empty stored credential is indistinguishable from a cleared one, so the
// caller must delete the row rather than seal nothing.
func TestSealRefusesEmpty(t *testing.T) {
	if _, _, err := newTestKeeper(t).Seal(nil); err == nil {
		t.Error("sealing an empty secret was allowed")
	}
}

func TestMalformedStoredValueIsRejected(t *testing.T) {
	k := newTestKeeper(t)
	for _, bad := range []string{"", "notv1.aa.bb", "v1.only-two-parts", "v1.!!!.###", "v1..", "v2.aa.bb"} {
		if _, err := k.Open(bad, KeyVersionLocalV1); err == nil {
			t.Errorf("malformed stored value %q was accepted", bad)
		}
	}
}

func TestKEKSizeIsEnforced(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewLocalKeeper(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte KEK was accepted; AES-256 needs exactly 32", n)
		}
	}
}

// The Keeper must own its KEK. A caller zeroing its own buffer after
// construction is correct behaviour, and must not silently break every Open.
func TestKeeperCopiesTheKEK(t *testing.T) {
	kek, _ := GenerateLocalKEK()
	k, err := NewLocalKeeper(kek)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _, err := k.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	Zero(kek) // the caller does the right thing
	if _, err := k.Open(sealed, KeyVersionLocalV1); err != nil {
		t.Fatalf("Keeper aliased the caller's KEK, so zeroing it broke decryption: %v", err)
	}
}

// §18.6 requires the local-KEK mode to warn. Silence here would be the same
// class of problem as the storm-protection gap: a real exposure nothing states.
func TestLocalKeeperWarnsLoudly(t *testing.T) {
	w := newTestKeeper(t).LocalKEKWarning()
	if w == "" {
		t.Fatal("the local-KEK mode returned no warning")
	}
	for _, want := range []string{"LOCALLY-HELD", "KMS or Vault"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning does not mention %q: %s", want, w)
		}
	}
}
