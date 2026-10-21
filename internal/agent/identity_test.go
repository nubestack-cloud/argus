package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// identity_test.go covers PROJECT.md B163: an agent must survive pod
// replacement with its identity intact, or refuse to run in a configuration
// where it cannot. Both halves are testable with a fake clientset — the whole
// point of the fix is that durable identity needs nothing from the
// infrastructure beyond an API server.

const testIdentitySecret = "argus-agent-identity"
const testIdentityNamespace = "argus-system"

// withFakeIdentityClientset points newIdentityStore/HasPersistedIdentity at a
// fake API server holding the given objects, for the duration of one test.
func withFakeIdentityClientset(t *testing.T, objects ...runtime.Object) *k8sfake.Clientset {
	t.Helper()
	clientset := k8sfake.NewSimpleClientset(objects...)
	previous := newIdentityClientset
	newIdentityClientset = func() (kubernetes.Interface, error) { return clientset, nil }
	t.Cleanup(func() { newIdentityClientset = previous })
	return clientset
}

func emptyIdentitySecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testIdentitySecret, Namespace: testIdentityNamespace},
		Type:       corev1.SecretTypeOpaque,
	}
}

func secretBackedConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		DataDir:                 t.TempDir(),
		IdentitySecretName:      testIdentitySecret,
		IdentitySecretNamespace: testIdentityNamespace,
	}
}

// TestIdentitySurvivesPodReplacement is B163's acceptance criterion, expressed
// as the sequence it describes: an agent enrolls, its pod is replaced (a new
// process, a brand-new empty DataDir — an emptyDir does not come back), and
// the replacement finds its identity and does NOT need a token or a second
// human accept.
func TestIdentitySurvivesPodReplacement(t *testing.T) {
	withFakeIdentityClientset(t, emptyIdentitySecret())

	// --- first pod: enrols and persists its identity ---
	first := secretBackedConfig(t)
	firstStore, err := newIdentityStore(first)
	if err != nil {
		t.Fatalf("newIdentityStore (first pod): %v", err)
	}
	for name, value := range map[string][]byte{
		certFileName:           []byte("CERT"),
		keyFileName:            []byte("KEY"),
		caFileName:             []byte("CA"),
		hubEndpointFileName:    []byte("hub.example.com:8443"),
		clusterIDFileName:      []byte("cl_01H"),
		planSigningKeyFileName: []byte("PLANKEY"),
		fingerprintFileName:    []byte("fp-abc"),
	} {
		if err := firstStore.write(name, value, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// --- pod replacement: same Secret, a different, empty DataDir ---
	second := secretBackedConfig(t)
	if second.DataDir == first.DataDir {
		t.Fatal("test bug: the replacement pod must get a fresh DataDir")
	}
	if !HasPersistedIdentity(second) {
		t.Fatal("HasPersistedIdentity() = false after a pod replacement — the agent would demand a fresh enrollment token and a repeat admin accept, which is exactly PROJECT.md B163")
	}
	secondStore, err := newIdentityStore(second)
	if err != nil {
		t.Fatalf("newIdentityStore (replacement pod): %v", err)
	}
	for name, want := range map[string]string{
		certFileName:           "CERT",
		keyFileName:            "KEY",
		caFileName:             "CA",
		hubEndpointFileName:    "hub.example.com:8443",
		clusterIDFileName:      "cl_01H",
		planSigningKeyFileName: "PLANKEY",
		fingerprintFileName:    "fp-abc",
	} {
		got, found, err := secondStore.read(name)
		if err != nil || !found {
			t.Errorf("read %s after pod replacement: found=%t err=%v — want the value the previous pod wrote", name, found, err)
			continue
		}
		if string(got) != want {
			t.Errorf("read %s = %q, want %q", name, got, want)
		}
	}
}

// TestEphemeralIdentityDoesNotSurvivePodReplacement is the same sequence
// against the opt-out mode, and is here so the contrast is a fact in the test
// suite rather than a claim in a comment: choosing `ephemeral` really does
// mean losing the enrollment.
func TestEphemeralIdentityDoesNotSurvivePodReplacement(t *testing.T) {
	first := Config{DataDir: t.TempDir()}
	store, err := newIdentityStore(first)
	if err != nil {
		t.Fatalf("newIdentityStore: %v", err)
	}
	if err := store.write(certFileName, []byte("CERT"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if !HasPersistedIdentity(first) {
		t.Fatal("HasPersistedIdentity() = false for the same DataDir it was just written to")
	}

	replacement := Config{DataDir: t.TempDir()} // a new pod's emptyDir
	if HasPersistedIdentity(replacement) {
		t.Fatal("HasPersistedIdentity() = true for a fresh DataDir — the ephemeral mode is supposed to be the mode that loses identity")
	}
}

// TestSecretStoreAdoptsAnExistingVolumeIdentity covers the upgrade path: an
// agent that was already enrolled with a PVC (persistence.enabled) must keep
// its identity when it moves to Secret-backed storage. Re-enrolling would need
// a human to accept the cluster again — a small version of the very failure
// B163 is about.
func TestSecretStoreAdoptsAnExistingVolumeIdentity(t *testing.T) {
	clientset := withFakeIdentityClientset(t, emptyIdentitySecret())

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, certFileName), []byte("OLDCERT"), 0o600); err != nil {
		t.Fatalf("seed the volume: %v", err)
	}

	cfg := Config{
		DataDir:                 dataDir,
		IdentitySecretName:      testIdentitySecret,
		IdentitySecretNamespace: testIdentityNamespace,
	}
	store, err := newIdentityStore(cfg)
	if err != nil {
		t.Fatalf("newIdentityStore: %v", err)
	}
	got, found, err := store.read(certFileName)
	if err != nil || !found || string(got) != "OLDCERT" {
		t.Fatalf("read cert = (%q, %t, %v), want (OLDCERT, true, nil)", got, found, err)
	}

	// And it was COPIED, not just read through: the next pod replacement has
	// no volume to read from.
	sec, err := clientset.CoreV1().Secrets(testIdentityNamespace).Get(t.Context(), testIdentitySecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get the identity Secret: %v", err)
	}
	if string(sec.Data[certFileName]) != "OLDCERT" {
		t.Errorf("the identity Secret holds %q for %s, want it to have adopted OLDCERT from the volume", sec.Data[certFileName], certFileName)
	}
}

// TestMissingIdentitySecretRefusesToStart is the other half of B163's
// acceptance criterion — "or the product refuses to install in a configuration
// where it cannot". A silent fallback to the ephemeral directory would be
// worse than the original defect: the operator would believe identity was
// durable and find out during a node drain.
func TestMissingIdentitySecretRefusesToStart(t *testing.T) {
	withFakeIdentityClientset(t) // no Secret at all

	_, err := newIdentityStore(secretBackedConfig(t))
	if err == nil {
		t.Fatal("newIdentityStore succeeded with no identity Secret — it must refuse rather than silently fall back to an identity that any pod replacement destroys")
	}
	for _, want := range []string{testIdentitySecret, "identity-secret.yaml", "identity.mode=ephemeral"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q — an operator has to be able to act on this without reading the source", err, want)
		}
	}
}

// TestForbiddenIdentitySecretRefusesToStartAndNamesTheGrant is the same
// refusal for the other realistic misconfiguration: the Secret exists but the
// Role was not applied. client-go's own message names neither the Role nor the
// verbs, so the agent has to.
func TestForbiddenIdentitySecretRefusesToStartAndNamesTheGrant(t *testing.T) {
	clientset := withFakeIdentityClientset(t, emptyIdentitySecret())
	clientset.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Resource: "secrets"}, testIdentitySecret, errors.New("RBAC: no policy matched"))
	})

	_, err := newIdentityStore(secretBackedConfig(t))
	if err == nil {
		t.Fatal("newIdentityStore succeeded although reading the identity Secret is forbidden")
	}
	for _, want := range []string{"get+update", testIdentitySecret} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestIdentitySecretNameWithoutNamespaceIsRejected guards the one
// half-configured state the chart cannot produce but a hand-rolled manifest
// can. Guessing a namespace here would mean writing an identity somewhere
// nobody looks for it.
func TestIdentitySecretNameWithoutNamespaceIsRejected(t *testing.T) {
	_, err := newIdentityStore(Config{DataDir: t.TempDir(), IdentitySecretName: testIdentitySecret})
	if err == nil {
		t.Fatal("newIdentityStore accepted an identity Secret name with no namespace")
	}
	if !strings.Contains(err.Error(), "ARGUS_AGENT_NAMESPACE") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// TestHasPersistedIdentityIsSilentAndSafeWhenUnresolvable pins the
// conservative direction of cmd/agent's precheck: when the answer cannot be
// determined, it must be "no identity" — which asks for an enrollment token a
// restart does not need, rather than starting an agent that can never enroll.
func TestHasPersistedIdentityIsSilentAndSafeWhenUnresolvable(t *testing.T) {
	previous := newIdentityClientset
	newIdentityClientset = func() (kubernetes.Interface, error) { return nil, errors.New("no kubeconfig") }
	t.Cleanup(func() { newIdentityClientset = previous })

	if HasPersistedIdentity(secretBackedConfig(t)) {
		t.Error("HasPersistedIdentity() = true although the API server is unreachable")
	}
}
