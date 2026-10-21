// Package secretbox is envelope encryption for the secrets ARGUS stores on an
// operator's behalf — today the Git provider token (REMEDIATION_ROADMAP.md
// D-R9), and anything else that follows.
//
// # Why this exists rather than another plaintext column
//
// `org_settings.llm_api_key` is stored in plaintext (migration 000018 says so in
// as many words), which is already out of compliance with DESIGN.md §18.6. A Git
// credential is a higher-value secret than an LLM key — it grants write access to
// the customer's source of truth — so it does not inherit that gap.
//
// D-R9 also made this load-bearing rather than defence in depth. Dropping the
// GitHub App means what sits at rest is a **live bearer token**, not a signing
// key that is useless without an installation: a leaked row is directly usable.
// So §18.6's other three rules stop being hygiene and become the actual control,
// and this package enforces the ones it can — see Open's contract on zeroing.
//
// # The shape, per §18.6
//
//	"At rest: envelope encryption. DEK per secret, KEK from an external KMS
//	 (AWS/GCP/Azure KMS, HashiCorp Vault) or a local key for evaluation only,
//	 with a loud warning. In the DB: ciphertext plus key version. Rotation
//	 re-wraps without re-encrypting payloads."
//
// A fresh 256-bit DEK per secret, AES-256-GCM for the payload, and the DEK
// wrapped by the KEK with AES-256-GCM again. `keyVersion` travels with the
// ciphertext so a future external-KMS KEK is a **re-wrap of DEKs**, not a
// re-encryption of payloads — which is the whole point of the envelope, and the
// reason taking the cheap KEK now costs nothing structural.
//
// v1 uses the local-KEK mode §18.6 explicitly permits. That is a deliberate
// owner decision, not an oversight, and Keeper.LocalKEKWarning exists so the
// deployment can say so out loud rather than implying a KMS it does not have.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeyVersionLocalV1 is the only key version this build writes: a locally-held
// KEK, per §18.6's evaluation mode.
//
// Stored beside every ciphertext rather than assumed, so introducing
// `kms-v1` later is an additive change — Open dispatches on what the row says,
// and rows written by the old version keep opening.
const KeyVersionLocalV1 = "local-v1"

// SigningKeyPurpose is the internal/data.LoadOrCreateSigningKey purpose that
// holds the local KEK. Named here rather than at the call site so there is one
// spelling of it: a typo would silently generate a *second* KEK, and every
// secret sealed under the first would stop opening.
const SigningKeyPurpose = "secret_kek_local_v1"

const (
	kekSize = 32 // AES-256
	dekSize = 32
)

// Keeper seals and opens secrets. Safe for concurrent use: it holds only the
// KEK and never mutates it.
type Keeper struct {
	kek []byte
	// external is false for the local-KEK mode. Reserved for the KMS
	// implementation so LocalKEKWarning can stop firing without callers
	// changing.
	external bool
}

// NewLocalKeeper wraps a locally-held KEK. Get the material from
// internal/data.LoadOrCreateSigningKey with SigningKeyPurpose, which already
// solves the "generate once, survive restarts, race-safe" problem for the JWT
// and enrollment signers.
func NewLocalKeeper(kek []byte) (*Keeper, error) {
	if len(kek) != kekSize {
		return nil, fmt.Errorf("secretbox: KEK must be %d bytes, got %d", kekSize, len(kek))
	}
	// Copied, not aliased: a caller that zeroes its buffer after construction
	// (which is the correct thing for a caller to do) would otherwise leave this
	// Keeper holding zeros and every Open failing with an authentication error
	// that looks like data corruption.
	own := make([]byte, kekSize)
	copy(own, kek)
	return &Keeper{kek: own}, nil
}

// GenerateLocalKEK is the `generate` callback for LoadOrCreateSigningKey.
func GenerateLocalKEK() ([]byte, error) {
	kek := make([]byte, kekSize)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("secretbox: generate KEK: %w", err)
	}
	return kek, nil
}

// LocalKEKWarning is the "loud warning" §18.6 requires, or "" once the KEK
// comes from a real KMS.
//
// Returned as a string for the caller to log rather than logged here, so the
// deployment decides where it goes — and so it appears once at startup instead
// of on every seal.
func (k *Keeper) LocalKEKWarning() string {
	if k.external {
		return ""
	}
	return "secrets are encrypted with a LOCALLY-HELD key: " +
		"anyone who can read this hub's database AND its signing_keys table can decrypt them, " +
		"so protect the database and its backups like the hub's own credentials. A KEK held in an " +
		"external KMS or Vault would close this; the stored key_version makes that a re-wrap rather " +
		"than a migration."
}

// Seal encrypts plaintext and returns an opaque, storable string plus the key
// version that opened it.
//
// The returned string is deliberately self-describing (`v1.<wrappedDEK>.<payload>`)
// rather than three columns: a secret and the DEK that opens it must move
// together, and splitting them across columns invites a partial write that
// produces an unopenable row.
func (k *Keeper) Seal(plaintext []byte) (ciphertext string, keyVersion string, err error) {
	if len(plaintext) == 0 {
		return "", "", errors.New("secretbox: refusing to seal an empty secret — an empty stored credential is indistinguishable from a cleared one, so the caller should delete the row instead")
	}

	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return "", "", fmt.Errorf("secretbox: generate DEK: %w", err)
	}
	// The DEK exists only to encrypt this one payload; it must not outlive the
	// call. Not a formality: it is the difference between a heap dump exposing
	// one secret and exposing every secret sealed since process start.
	defer zero(dek)

	payload, err := sealWith(dek, plaintext)
	if err != nil {
		return "", "", fmt.Errorf("secretbox: encrypt payload: %w", err)
	}
	wrapped, err := sealWith(k.kek, dek)
	if err != nil {
		return "", "", fmt.Errorf("secretbox: wrap DEK: %w", err)
	}

	return strings.Join([]string{"v1", b64(wrapped), b64(payload)}, "."), KeyVersionLocalV1, nil
}

// Open decrypts what Seal produced.
//
// **The caller owns zeroing the returned plaintext** once it has finished with
// it. This package cannot do that — it does not know when the caller is done —
// and §18.6 requires it ("in memory: zeroed after use"), so it is stated here
// rather than left to be inferred. Zero() is exported for exactly this.
func (k *Keeper) Open(ciphertext string, keyVersion string) ([]byte, error) {
	if keyVersion != "" && keyVersion != KeyVersionLocalV1 {
		// A row written by a KEK this build does not have. Refused explicitly
		// rather than attempted-and-failed, so the error says "wrong key" and
		// not "authentication failed", which would read as corruption.
		return nil, fmt.Errorf("secretbox: secret was sealed with key version %q; this build only holds %q", keyVersion, KeyVersionLocalV1)
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, errors.New("secretbox: stored secret is not in the expected v1.<dek>.<payload> form")
	}
	wrapped, err := unb64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("secretbox: decode wrapped DEK: %w", err)
	}
	payload, err := unb64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("secretbox: decode payload: %w", err)
	}

	dek, err := openWith(k.kek, wrapped)
	if err != nil {
		// Deliberately does not echo the ciphertext or any part of it.
		return nil, fmt.Errorf("secretbox: unwrap DEK: %w", err)
	}
	defer zero(dek)

	plaintext, err := openWith(dek, payload)
	if err != nil {
		return nil, fmt.Errorf("secretbox: decrypt payload: %w", err)
	}
	return plaintext, nil
}

// Zero overwrites b. Exported because Open's contract makes zeroing the
// caller's job.
func Zero(b []byte) { zero(b) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sealWith is AES-256-GCM with a random nonce prefixed to the output. GCM
// rather than CBC or CTR because a stored secret needs to be tamper-evident,
// not merely unreadable: a bit-flipped ciphertext must fail loudly rather than
// decrypt to garbage a caller might then use as a token.
func sealWith(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func openWith(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed value is shorter than a nonce")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		// GCM's own error text is deliberately uninformative; keep it that way
		// rather than adding detail that would help an attacker distinguish
		// "wrong key" from "tampered payload".
		return nil, errors.New("authentication failed — wrong key, or the stored value was altered")
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
