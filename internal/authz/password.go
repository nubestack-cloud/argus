// Package authz implements the capability/scope grammar and enforcement described
// in lld/02-authz-spec.md.
package authz

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. lld/02-authz-spec.md §8 specifies Argon2id for local
// passwords without pinning parameters — these are a reasonable default for a
// server-side hash (not a first-factor-only mobile app), revisit under real load.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLength is the shipped DEFAULT floor a user-CHOSEN password
// (self-service change, PUT /api/v1/users/me/password) must clear — migration
// 000131's org_settings.min_password_length column DEFAULT, and the fallback
// ValidatePasswordStrength's caller should pass when it has no resolved
// settings.Config to hand (there is none in this package today; every real
// caller goes through handleChangePassword, which always has one). Operator-
// adjustable since migration 000131 via PUT /api/v1/admin/settings — see that
// migration's doc comment for the full rationale, including why this was
// promoted from a hardcoded constant to a column rather than gaining an
// env-var tier. lld/02-authz-spec.md §8 doesn't mandate a complexity rules
// engine, so this is deliberately just a length check, not a character-class
// policy — a length-only rule is both simpler to implement correctly and, per
// current NIST guidance, more effective than forced complexity rules at
// actually resisting guessing attacks. generateTemporaryPassword's
// server-generated passwords (internal/api/users.go, 160 random bits) always
// clear this by a wide margin regardless, so it is deliberately never applied
// to that path.
const MinPasswordLength = 12

// ValidatePasswordStrength enforces minLength (callers pass the resolved
// settings.Config.MinPasswordLength, falling back to MinPasswordLength when
// none is available). Called by PUT /api/v1/users/me/password before
// accepting a self-chosen new password — never called on a server-generated
// temporary password (see MinPasswordLength's doc comment).
func ValidatePasswordStrength(password string, minLength int) error {
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}
	return nil
}

// HashPassword returns a self-describing Argon2id hash string
// ($argon2id$v=19$m=...,t=...,p=...$salt$hash), so verification never needs
// out-of-band knowledge of which parameters were used to create a given hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword checks a password against a hash produced by HashPassword.
// Comparison is constant-time (subtle.ConstantTimeCompare) — the same discipline
// lld/01-threat-model.md SR-19 requires for approval/plan signatures, applied here
// too since a timing side-channel on password verification is the identical class
// of vulnerability.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("unrecognized hash format")
	}
	var version int
	var mem, timeCost, threads int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &timeCost, &threads); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	wantHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	gotHash := argon2.IDKey([]byte(password), salt, uint32(timeCost), uint32(mem), uint8(threads), uint32(len(wantHash)))
	return subtle.ConstantTimeCompare(wantHash, gotHash) == 1, nil
}
