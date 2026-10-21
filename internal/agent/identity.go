// identity.go is PROJECT.md B163: where this agent keeps the identity the hub
// issued it — its private key, its signed leaf certificate, the tunnel CA, the
// hub endpoint, its per-cluster remediation plan signing key, its hub-assigned
// cluster id, and its cluster fingerprint.
//
// THE PROBLEM. All seven used to live only in ARGUS_AGENT_DATA_DIR,
// which the chart backs with an emptyDir by default. So ANY pod replacement —
// a node drain, an eviction, a `kubectl rollout restart`, a resource-limit
// edit, a `helm upgrade` — destroyed the identity, and the cluster then needed
// a fresh enrollment token AND a repeat human "accept" on the hub before it
// reconnected. A routine, everyday Kubernetes operation permanently
// disconnected a cluster and needed an operator to notice and repair it.
//
// WHY NOT SIMPLY TURN THE PVC ON. The chart's recorded reason for
// persistence.enabled: false is sound and still stands: it targets a fleet of
// 200+ heterogeneous clusters and cannot assume any of them provisions a
// usable default StorageClass, so defaulting a PVC on would break `helm
// install` wherever there is none. A ReadWriteOnce PVC is also the wrong shape
// for the failure this is about — on a node-local provisioner the claim binds
// the pod to one node, so the node-loss case either loses the volume anyway or
// leaves the replacement pod Pending.
//
// WHAT THIS DOES INSTEAD. The identity lives in a Kubernetes Secret in the
// agent's own namespace, which needs no StorageClass, survives node loss, and
// is reachable from wherever the replacement pod is scheduled. The Secret is
// created by the chart (deploy/helm/argus-agent/templates/identity-secret.yaml)
// and the agent is granted `get` and `update` on that ONE name in its own
// namespace — never `create` (which RBAC cannot restrict by name) and never a
// widening of templates/clusterrole.yaml's deliberate "no Secret access beyond
// a single named get" posture.
//
// This adds no new class of exposure. The chart ALREADY stores the enrollment
// token — the credential that lets a party enroll as this cluster in the first
// place — as a Secret in this same namespace (templates/secret.yaml,
// values.yaml's enrollment.tokenSecretRef). A party who can read Secrets in
// argus-system can already take this cluster's identity; holding the issued
// leaf next to the token that issues it does not change who can do what. Both
// alternatives are equivalent in practice too: an emptyDir is readable by
// anyone with node-level access, which is the same bar.
//
// FAILING RATHER THAN PRETENDING. When a Secret is configured but unusable
// (absent, or RBAC denied), Run fails with a message naming exactly what is
// missing instead of falling back to the ephemeral directory. A silent
// fallback would reproduce B163 invisibly — the operator would believe
// identity was durable and find out during a node drain. The ephemeral
// directory is still reachable, but only by explicitly asking for it
// (identity.mode=ephemeral in the chart, which unsets the env var), and it
// says so in the log on every start.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"os"
	"path/filepath"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// newIdentityClientset is how this file reaches the API server, as a variable
// so identity_test.go can substitute a fake clientset. Production always uses
// facts.go's newClientset (in-cluster config, then $KUBECONFIG, then
// ~/.kube/config) — there is no second real implementation and no way to
// select one from configuration.
var newIdentityClientset = func() (kubernetes.Interface, error) { return newClientset() }

// identityStore is where one agent's identity is read from and written to.
// Two implementations: secretStore (durable, the chart's default) and dirStore
// (the pre-B163 behaviour, which an operator must now explicitly choose).
//
// Deliberately the same read/write shape the file paths had, so the enrollment
// flow's ordering — persist the key BEFORE the network call, so a retry reuses
// it rather than generating a second one — is unchanged by this indirection.
type identityStore interface {
	// read returns the stored value for name. found is false, with a nil
	// error, when this store is reachable but holds no such value yet: the
	// normal state before a first enrollment.
	read(name string) (data []byte, found bool, err error)
	// write stores data under name. perm applies only to a file-backed
	// store; a Secret's permissions are the API server's business.
	write(name string, data []byte, perm os.FileMode) error
	// describe names this store for the startup log and for the error
	// messages an operator has to act on.
	describe() string
}

// --- ephemeral, file-backed ---

type dirStore struct{ dir string }

func newDirStore(dir string) (*dirStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dir, err)
	}
	return &dirStore{dir: dir}, nil
}

func (d *dirStore) read(name string) ([]byte, bool, error) {
	data, err := os.ReadFile(filepath.Join(d.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (d *dirStore) write(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filepath.Join(d.dir, name), data, perm)
}

func (d *dirStore) describe() string { return "directory " + d.dir }

// --- durable, Secret-backed ---

// secretStore keeps the identity in one Secret in the agent's own namespace.
//
// Reads go straight to the API server rather than to a cached copy: this is a
// handful of calls at startup, and a stale cache here would mean enrolling a
// second time for a cluster that already has an identity.
type secretStore struct {
	secrets   kubernetes.Interface
	namespace string
	name      string

	// adoptFrom is an optional read-only fallback, consulted only when the
	// Secret holds no value for a key. It is what carries an already-enrolled
	// agent's identity across the switch to Secret-backed storage — an agent
	// that had a PVC (persistence.enabled) keeps its identity on upgrade
	// instead of re-enrolling and needing a human to accept it again, which
	// would be a small version of the very problem B163 is about. Writes
	// never go here.
	adoptFrom identityStore

	// mu serializes read-modify-write on the Secret. One process, and the
	// enrollment flow is sequential, but write() is a get-then-update and
	// this makes that obviously safe rather than incidentally safe.
	mu sync.Mutex
}

func (s *secretStore) read(name string) ([]byte, bool, error) {
	sec, err := s.secrets.CoreV1().Secrets(s.namespace).Get(context.Background(), s.name, metav1.GetOptions{})
	if err != nil {
		return nil, false, s.explain(err)
	}
	if data, ok := sec.Data[name]; ok && len(data) > 0 {
		return data, true, nil
	}
	if s.adoptFrom != nil {
		data, found, err := s.adoptFrom.read(name)
		if err == nil && found {
			logger.Info("adopting an identity value into its durable Secret — this agent keeps its identity instead of re-enrolling",
				slog.String("value", name), slog.String("from", s.adoptFrom.describe()), slog.String("namespace", s.namespace), slog.String("secret", s.name))
			if werr := s.write(name, data, 0o600); werr != nil {
				// Not fatal: the value is in hand, so this start works. It
				// just means the next pod replacement will adopt it again,
				// or (if the old volume is gone) re-enroll.
				logger.Warn("could not copy an identity value into its durable Secret — identity is NOT durable until this succeeds",
					slog.String("value", name), slog.String("namespace", s.namespace), slog.String("secret", s.name), logging.Err(werr))
			}
			return data, true, nil
		}
	}
	return nil, false, nil
}

func (s *secretStore) write(name string, data []byte, _ os.FileMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	// Read-modify-write, retried once: the only writer is this process, so a
	// conflict means the chart's own apply landed between the get and the
	// update, and retrying resolves it.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		sec, err := s.secrets.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
		if err != nil {
			return s.explain(err)
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[name] = data
		if _, err := s.secrets.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
			lastErr = err
			if apierrors.IsConflict(err) {
				continue
			}
			return s.explain(err)
		}
		return nil
	}
	return s.explain(lastErr)
}

func (s *secretStore) describe() string {
	return fmt.Sprintf("Secret %s/%s", s.namespace, s.name)
}

// explain turns an API error into something an operator can act on. A
// NotFound or a Forbidden here is a deployment problem with exactly one fix
// each, and the raw client-go message names neither.
func (s *secretStore) explain(err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return fmt.Errorf("identity Secret %s/%s does not exist — it is created by deploy/helm/argus-agent (templates/identity-secret.yaml); create it, or set identity.mode=ephemeral to accept an identity that is lost on any pod replacement: %w",
			s.namespace, s.name, err)
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return fmt.Errorf("this agent's ServiceAccount may not read/write identity Secret %s/%s — it needs get+update on that one name (deploy/helm/argus-agent/templates/identity-secret.yaml's Role): %w",
			s.namespace, s.name, err)
	default:
		return fmt.Errorf("identity Secret %s/%s: %w", s.namespace, s.name, err)
	}
}

// newIdentityStore resolves where this agent's identity lives, from config
// alone — no environment reads (this package never reads the environment; see
// Config's doc comment) — and reports what it resolved, because "is this
// cluster's enrollment durable?" is the first thing an operator reading these
// logs after a disconnection needs to know.
//
// IdentitySecretName empty selects the ephemeral directory. A configured
// Secret that cannot be reached is an error, never a silent downgrade: see
// this file's header on why.
func newIdentityStore(cfg Config) (identityStore, error) {
	store, err := resolveIdentityStore(cfg, true)
	if err != nil {
		return nil, err
	}
	// Probe once, here, rather than letting the first read fail inside the
	// enrollment flow: a missing Secret or a missing Role is a deployment
	// problem, and it belongs in the first lines of the log.
	if _, _, err := store.read(certFileName); err != nil {
		return nil, err
	}
	return store, nil
}

// HasPersistedIdentity reports whether an identity for this configuration
// already exists — what cmd/agent uses to tell a first enrollment (where an
// enrollment token is required) from a restart (where it is not).
//
// Deliberately silent and best-effort: any problem resolving or reading the
// store answers false, and Run's own resolution a moment later reports the
// real reason with the detail an operator can act on. Answering false when the
// truth is unknown is also the safe direction — it asks for a token that a
// restart does not need, rather than starting a hub-less agent that can never
// enroll.
func HasPersistedIdentity(cfg Config) bool {
	store, err := resolveIdentityStore(cfg, false)
	if err != nil {
		return false
	}
	_, found, err := store.read(certFileName)
	return err == nil && found
}

func resolveIdentityStore(cfg Config, verbose bool) (identityStore, error) {
	dir, err := newDirStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.IdentitySecretName == "" {
		if verbose {
			logger.Warn("identity is stored somewhere that does NOT survive pod replacement — a node drain, eviction or `helm upgrade` loses this cluster's enrollment, needing a fresh enrollment token and a repeat admin accept on the hub; durable identity is deploy/helm/argus-agent's default, and this process was started without it",
				slog.String("store", dir.describe()))
		}
		return dir, nil
	}
	if cfg.IdentitySecretNamespace == "" {
		return nil, errors.New("agent: an identity Secret name was configured with no namespace — the chart sets both (ARGUS_AGENT_IDENTITY_SECRET and ARGUS_AGENT_NAMESPACE)")
	}

	clientset, err := newIdentityClientset()
	if err != nil {
		return nil, fmt.Errorf("agent: identity Secret %s/%s was configured, but this process has no usable Kubernetes config to reach it (%w) — set identity.mode=ephemeral only if an identity lost on every pod replacement is genuinely acceptable",
			cfg.IdentitySecretNamespace, cfg.IdentitySecretName, err)
	}
	store := &secretStore{
		secrets:   clientset,
		namespace: cfg.IdentitySecretNamespace,
		name:      cfg.IdentitySecretName,
		adoptFrom: dir,
	}
	if verbose {
		logger.Info("identity is stored durably — it survives pod replacement", slog.String("store", store.describe()))
	}
	return store, nil
}
