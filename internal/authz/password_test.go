package authz

import "testing"

func TestHashAndVerifyPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("correct-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("VerifyPassword returned false for the correct password")
	}
}

func TestVerifyPassword_WrongPasswordRejected(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("VerifyPassword returned true for an incorrect password")
	}
}

func TestHashPassword_UniqueSaltPerCall(t *testing.T) {
	// Two hashes of the same password must differ (distinct random salts) — a
	// deterministic hash would make offline rainbow-table attacks trivial across
	// every user who happens to share a password.
	h1, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	h2, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if h1 == h2 {
		t.Error("HashPassword produced identical output for two calls with the same password — salt is not being randomized")
	}
}

func TestVerifyPassword_RejectsMalformedHash(t *testing.T) {
	if _, err := VerifyPassword("anything", "not-a-real-hash"); err == nil {
		t.Error("VerifyPassword should return an error for a malformed hash, not silently proceed")
	}
}

// TestValidatePasswordStrength is the DB-free unit test for
// PUT /api/v1/users/me/password's "reasonable minimum length" requirement —
// a length-only floor, deliberately not a character-class complexity rules
// engine (see ValidatePasswordStrength's doc comment).
func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty password is rejected", "", true},
		{"one character short of the minimum is rejected", string(make([]byte, MinPasswordLength-1)), true},
		{"exactly the minimum length is accepted", string(make([]byte, MinPasswordLength)), false},
		{"well over the minimum length is accepted", "a-genuinely-long-passphrase-like-this-one", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tc.password, MinPasswordLength)
			if tc.wantErr && err == nil {
				t.Errorf("ValidatePasswordStrength(%q) = nil, want an error", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidatePasswordStrength(%q) = %v, want no error", tc.password, err)
			}
		})
	}
}

// TestValidatePasswordStrength_ConfiguredMinLength covers the
// migration-000131 case ValidatePasswordStrength's bare-length-check cases
// above can't: a minLength OTHER than the shipped default, as a request on a
// tenant that configured org_settings.min_password_length would pass.
func TestValidatePasswordStrength_ConfiguredMinLength(t *testing.T) {
	if err := ValidatePasswordStrength("short", 20); err == nil {
		t.Error("a 5-character password should fail a configured 20-character minimum")
	}
	if err := ValidatePasswordStrength("exactly-twenty-chars", 20); err != nil {
		t.Errorf("a 20-character password should pass a configured 20-character minimum, got %v", err)
	}
	if err := ValidatePasswordStrength("ok", 1); err != nil {
		t.Errorf("a configured minimum of 1 should accept any non-empty password, got %v", err)
	}
}
