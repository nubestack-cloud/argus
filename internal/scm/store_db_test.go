package scm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/secretbox"
)

// UpdateBinding exists to close two gaps SaveBinding's upsert-by-repo_key
// contract leaves — see its own doc comment. These tests pin exactly those
// two gaps, plus the token-optional and expiry-three-state contracts that
// make it safe to use for a small edit without resending everything:
//
//  1. A field NOT in the patch survives untouched (SaveBinding's own
//     rotate-by-repeating-the-URL path is a full overwrite and would wipe it).
//  2. Changing the URL is possible, and colliding with a DIFFERENT existing
//     binding's repo_key is refused rather than silently merged.

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	kek, err := secretbox.GenerateLocalKEK()
	if err != nil {
		t.Fatalf("GenerateLocalKEK: %v", err)
	}
	keeper, err := secretbox.NewLocalKeeper(kek)
	if err != nil {
		t.Fatalf("NewLocalKeeper: %v", err)
	}
	return NewStore(keeper)
}

// scopedTx begins a transaction scoped to tenantID and registers its
// rollback — every call in these tests either commits explicitly (to make a
// change visible to a LATER, separate transaction) or lets this rollback,
// matching objectmapping_db_test.go's own pattern in this same package.
func scopedTx(t *testing.T, pool *pgxpool.Pool, tenantID string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return tx
}

// saveTestBinding registers one throwaway binding via the real SaveBinding
// path (not a hand-written INSERT) so these tests exercise UpdateBinding
// against exactly the row shape SaveBinding actually produces, and registers
// its cleanup — deleting this one row and its one secret by id, never a
// scoped sweep (CLAUDE.md's own warning about DB-test cleanup destroying
// real development data twice already is about broad WHERE clauses, not
// precise by-id deletes like this one).
func saveTestBinding(t *testing.T, pool *pgxpool.Pool, store *Store, tenantID string, in Binding, token []byte) Binding {
	t.Helper()
	ctx := context.Background()
	tx := scopedTx(t, pool, tenantID)
	saved, err := store.SaveBinding(ctx, tx, tenantID, in, token)
	if err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("SaveBinding: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit SaveBinding: %v", err)
	}
	t.Cleanup(func() {
		cleanupTx := scopedTx(t, pool, tenantID)
		defer cleanupTx.Rollback(ctx) //nolint:errcheck
		// Both the credential this binding was registered with AND whatever
		// credential it carries NOW — a test that rotates the token
		// (TestUpdateBinding_TokenRotationReplacesCredentialAndDeletesTheOldOne)
		// leaves a different row than the one saved.CredentialRef names, and
		// UpdateBinding has already deleted the superseded one, so deleting
		// only the original removed nothing and leaked the replacement, one
		// encrypted_secrets row per run (PROJECT.md B175). Read from the
		// binding rather than passed in by each caller, so a future test that
		// rotates is covered without remembering to. Runs before the binding
		// row is deleted, because that subquery needs it.
		if _, err := cleanupTx.Exec(ctx,
			`DELETE FROM encrypted_secrets
			  WHERE id = $1
			     OR id = (SELECT credential_ref FROM repository_bindings WHERE id = $2)`,
			saved.CredentialRef, saved.ID); err != nil {
			t.Errorf("cleanup delete secret: %v", err)
			return
		}
		if _, err := cleanupTx.Exec(ctx, `DELETE FROM repository_bindings WHERE id = $1`, saved.ID); err != nil {
			t.Errorf("cleanup delete binding: %v", err)
			return
		}
		if err := cleanupTx.Commit(ctx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})
	return saved
}

func rawSpec(t *testing.T, pool *pgxpool.Pool, tenantID, id string) []byte {
	t.Helper()
	ctx := context.Background()
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(ctx) //nolint:errcheck
	var spec []byte
	if err := tx.QueryRow(ctx, `SELECT spec FROM repository_bindings WHERE id = $1`, id).Scan(&spec); err != nil {
		t.Fatalf("read spec: %v", err)
	}
	return spec
}

func TestUpdateBinding_UntouchedFieldsSurvivePartialUpdate(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "github", URL: "https://github.com/example/untouched-fields.git",
		APIBaseURL: "https://ghe.example/api/v3", DefaultBranch: "main",
		ObjectMappings: []ObjectMapping{{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"}},
	}, []byte("original-token"))

	// Patch ONLY DefaultBranch. Everything else — including the field
	// SaveBinding's own rotate-by-URL path would have silently wiped if this
	// caller had forgotten to resend it — must come back unchanged.
	newBranch := "release"
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID,
		BindingPatch{DefaultBranch: &newBranch}, nil)
	if err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if updated.DefaultBranch != "release" {
		t.Errorf("DefaultBranch = %q, want %q", updated.DefaultBranch, "release")
	}
	if updated.APIBaseURL != "https://ghe.example/api/v3" {
		t.Errorf("APIBaseURL = %q, want it untouched (was %q)", updated.APIBaseURL, "https://ghe.example/api/v3")
	}
	if updated.URL != saved.URL {
		t.Errorf("URL = %q, want it untouched", updated.URL)
	}
	if updated.CredentialRef != saved.CredentialRef {
		t.Errorf("CredentialRef changed to %q from %q, want it untouched — no token was supplied", updated.CredentialRef, saved.CredentialRef)
	}

	if len(updated.ObjectMappings) != 1 || updated.ObjectMappings[0].ReleaseName != "payments" {
		t.Errorf("ObjectMappings = %+v, want the original untouched \"payments\" mapping still there", updated.ObjectMappings)
	}

	spec := rawSpec(t, pool, tenantID, saved.ID)
	if !strings.Contains(string(spec), `"payments"`) {
		t.Errorf("spec no longer contains the original objectMapping's release name — a partial update must not touch fields it wasn't asked to change: %s", spec)
	}
}

func TestUpdateBinding_ObjectMappingsReplaceWhenPatched(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "github", URL: "https://github.com/example/replace-mappings.git",
		ObjectMappings: []ObjectMapping{{ReleaseName: "old-release", Namespace: "prod", Path: "envs/prod/old"}},
	}, []byte("original-token"))

	newMappings := []ObjectMapping{{ReleaseName: "new-release", Namespace: "prod", Path: "envs/prod/new"}}
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID,
		BindingPatch{ObjectMappings: &newMappings}, nil)
	if err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if len(updated.ObjectMappings) != 1 || updated.ObjectMappings[0].ReleaseName != "new-release" {
		t.Errorf("UpdateBinding's own return value ObjectMappings = %+v, want just the new \"new-release\" mapping", updated.ObjectMappings)
	}

	spec := rawSpec(t, pool, tenantID, saved.ID)
	if strings.Contains(string(spec), "old-release") {
		t.Errorf("spec still contains the superseded mapping: %s", spec)
	}
	if !strings.Contains(string(spec), "new-release") {
		t.Errorf("spec does not contain the new mapping: %s", spec)
	}
}

func TestUpdateBinding_ChangingURLMovesRepoKeyAndAllowsFindingItByTheNewOne(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "github", URL: "https://github.com/example/old-name.git",
	}, []byte("token"))

	newURL := "https://github.com/example/new-name.git"
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID, BindingPatch{URL: &newURL}, nil)
	if err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if updated.URL != newURL {
		t.Errorf("URL = %q, want %q", updated.URL, newURL)
	}

	// Re-registering the OLD url now must NOT collide with this binding —
	// it moved, it didn't fork into two rows.
	reTx := scopedTx(t, pool, tenantID)
	defer reTx.Rollback(context.Background()) //nolint:errcheck
	reSaved, err := store.SaveBinding(context.Background(), reTx, tenantID,
		Binding{Provider: "github", URL: "https://github.com/example/old-name.git"}, []byte("a-different-token"))
	if err != nil {
		t.Fatalf("re-registering the vacated old URL should succeed as a fresh binding: %v", err)
	}
	if err := reTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		cleanupTx := scopedTx(t, pool, tenantID)
		defer cleanupTx.Rollback(context.Background())                                                             //nolint:errcheck
		cleanupTx.Exec(context.Background(), `DELETE FROM encrypted_secrets WHERE id = $1`, reSaved.CredentialRef) //nolint:errcheck
		cleanupTx.Exec(context.Background(), `DELETE FROM repository_bindings WHERE id = $1`, reSaved.ID)          //nolint:errcheck
		cleanupTx.Commit(context.Background())                                                                     //nolint:errcheck
	})
}

func TestUpdateBinding_URLConflictingWithAnotherBindingIsRefused(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	a := saveTestBinding(t, pool, store, tenantID, Binding{Provider: "github", URL: "https://github.com/example/repo-a.git"}, []byte("token-a"))
	b := saveTestBinding(t, pool, store, tenantID, Binding{Provider: "github", URL: "https://github.com/example/repo-b.git"}, []byte("token-b"))

	// Try to make B's URL the same as A's — must be refused, not silently
	// merge two bindings (and their two, now-ambiguous, credentials) into one.
	sameAsA := a.URL
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	_, err := store.UpdateBinding(context.Background(), tx, tenantID, b.ID, BindingPatch{URL: &sameAsA}, nil)
	if !errors.Is(err, ErrRepoKeyConflict) {
		t.Fatalf("UpdateBinding(B's url -> A's url) error = %v, want ErrRepoKeyConflict", err)
	}
}

func TestUpdateBinding_TokenRotationReplacesCredentialAndDeletesTheOldOne(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "github", URL: "https://github.com/example/rotate-token.git",
	}, []byte("old-token"))
	oldCredentialRef := saved.CredentialRef

	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID, BindingPatch{}, []byte("new-token"))
	if err != nil {
		t.Fatalf("UpdateBinding: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if updated.CredentialRef == oldCredentialRef {
		t.Fatal("CredentialRef did not change after supplying a new token")
	}

	verifyTx := scopedTx(t, pool, tenantID)
	defer verifyTx.Rollback(context.Background()) //nolint:errcheck
	var ciphertext, keyVersion string
	if err := verifyTx.QueryRow(context.Background(),
		`SELECT ciphertext, key_version FROM encrypted_secrets WHERE id = $1`, updated.CredentialRef,
	).Scan(&ciphertext, &keyVersion); err != nil {
		t.Fatalf("read new secret: %v", err)
	}
	plaintext, err := store.keeper.Open(ciphertext, keyVersion)
	if err != nil {
		t.Fatalf("decrypt new secret: %v", err)
	}
	if string(plaintext) != "new-token" {
		t.Errorf("stored credential = %q, want %q", plaintext, "new-token")
	}

	var stillThere bool
	if err := verifyTx.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM encrypted_secrets WHERE id = $1)`, oldCredentialRef,
	).Scan(&stillThere); err != nil {
		t.Fatalf("check old secret: %v", err)
	}
	if stillThere {
		t.Error("the superseded credential is still in encrypted_secrets — token rotation must delete it, not leak it forever")
	}
}

func TestUpdateBinding_ExpiryThreeStates(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")
	originalExpiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "github", URL: "https://github.com/example/expiry.git", CredentialExpiresAt: &originalExpiry,
	}, []byte("token"))

	t.Run("not mentioning ExpiresAt leaves it alone", func(t *testing.T) {
		branch := "main"
		tx := scopedTx(t, pool, tenantID)
		defer tx.Rollback(context.Background()) //nolint:errcheck
		updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID, BindingPatch{DefaultBranch: &branch}, nil)
		if err != nil {
			t.Fatalf("UpdateBinding: %v", err)
		}
		if updated.CredentialExpiresAt == nil || !updated.CredentialExpiresAt.Equal(originalExpiry) {
			t.Errorf("CredentialExpiresAt = %v, want it untouched at %v", updated.CredentialExpiresAt, originalExpiry)
		}
	})

	t.Run("ExpiresAtProvided with a value changes it", func(t *testing.T) {
		newExpiry := time.Date(2028, 6, 15, 0, 0, 0, 0, time.UTC)
		tx := scopedTx(t, pool, tenantID)
		defer tx.Rollback(context.Background()) //nolint:errcheck
		updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID,
			BindingPatch{ExpiresAtProvided: true, CredentialExpiresAt: &newExpiry}, nil)
		if err != nil {
			t.Fatalf("UpdateBinding: %v", err)
		}
		if updated.CredentialExpiresAt == nil || !updated.CredentialExpiresAt.Equal(newExpiry) {
			t.Errorf("CredentialExpiresAt = %v, want %v", updated.CredentialExpiresAt, newExpiry)
		}
	})

	t.Run("ExpiresAtProvided with nil explicitly clears it", func(t *testing.T) {
		tx := scopedTx(t, pool, tenantID)
		defer tx.Rollback(context.Background()) //nolint:errcheck
		updated, err := store.UpdateBinding(context.Background(), tx, tenantID, saved.ID,
			BindingPatch{ExpiresAtProvided: true, CredentialExpiresAt: nil}, nil)
		if err != nil {
			t.Fatalf("UpdateBinding: %v", err)
		}
		if updated.CredentialExpiresAt != nil {
			t.Errorf("CredentialExpiresAt = %v, want nil (cleared)", updated.CredentialExpiresAt)
		}
	})
}

func TestUpdateBinding_UnknownIDIsErrNoBinding(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	branch := "main"
	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	_, err := store.UpdateBinding(context.Background(), tx, tenantID, "rb_does-not-exist", BindingPatch{DefaultBranch: &branch}, nil)
	if !errors.Is(err, ErrNoBinding) {
		t.Fatalf("UpdateBinding(unknown id) error = %v, want ErrNoBinding", err)
	}
}

func TestUpdateBinding_RLSHidesAnotherTenantsBinding(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantA := domain.NewID("scmtesttenanta")
	tenantB := domain.NewID("scmtesttenantb")

	saved := saveTestBinding(t, pool, store, tenantA, Binding{
		Provider: "github", URL: "https://github.com/example/rls-update.git",
	}, []byte("token"))

	// tenantB's transaction cannot even see tenantA's row — this must read as
	// ErrNoBinding, never as a successful update of someone else's binding.
	branch := "main"
	tx := scopedTx(t, pool, tenantB)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	_, err := store.UpdateBinding(context.Background(), tx, tenantB, saved.ID, BindingPatch{DefaultBranch: &branch}, nil)
	if !errors.Is(err, ErrNoBinding) {
		t.Fatalf("UpdateBinding(tenantB, tenantA's binding) error = %v, want ErrNoBinding — RLS isolation is broken", err)
	}
}

// ListBindings used to leave ObjectMappings zero on every row (deliberately,
// per its own old doc comment — a list response never needed the write
// policy). That stopped being true the moment an editing UI needed to
// pre-fill from it: without this, "edit the mappings" could only ever mean
// "send a fresh list and hope," since there would be no way to show what was
// already configured.
func TestListBindings_PopulatesObjectMappings(t *testing.T) {
	pool := testPool(t)
	store := newStoreForTest(t)
	tenantID := domain.NewID("scmtesttenant")

	saved := saveTestBinding(t, pool, store, tenantID, Binding{
		Provider: "gitlab", URL: "https://gitlab.internal.example/shop/shop-apps-helm.git",
		ObjectMappings: []ObjectMapping{{ReleaseName: "shop-apps-helm", Namespace: "shop", Path: "envs/shop/values.yaml"}},
	}, []byte("token"))

	tx := scopedTx(t, pool, tenantID)
	defer tx.Rollback(context.Background()) //nolint:errcheck
	bindings, err := store.ListBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}

	var found *Binding
	for i := range bindings {
		if bindings[i].ID == saved.ID {
			found = &bindings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("ListBindings did not return the binding just saved (id %s)", saved.ID)
	}
	if len(found.ObjectMappings) != 1 {
		t.Fatalf("ObjectMappings = %+v, want exactly 1 entry", found.ObjectMappings)
	}
	m := found.ObjectMappings[0]
	if m.ReleaseName != "shop-apps-helm" || m.Namespace != "shop" || m.Path != "envs/shop/values.yaml" {
		t.Errorf("ObjectMappings[0] = %+v, want the release/namespace/path exactly as saved", m)
	}
}
