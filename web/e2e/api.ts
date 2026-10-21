// Small hub-API client used only by the e2e harness itself (global setup/
// teardown, and any spec that needs to seed/inspect state the UI has no
// control for) — deliberately NOT a re-export of src/api/client.ts. That
// file is app code bundled for the browser; importing it here would pull a
// browser-only module (and its whole dependency graph) into Node, for the
// sake of two calls this file can make directly against the same JSON
// contract with `fetch`. Node 18+ (this repo's CI targets Node 22) has a
// global `fetch`, so no extra dependency is needed either.
//
// BACKLOG.md P3: this suite runs against a REAL hub, not a mock — these
// helpers exist to seed and clear known data (internal/api/demo_data.go's
// POST/DELETE /api/v1/demo-data) around the actual UI flows the specs drive
// through a real browser.

// Fixed dev-only credential — never a production value. This is RUNBOOK.md's
// documented local login ("admin@localhost / dev-admin-password-123").
//
// IT DOES NOT MATCH deploy/compose/docker-compose.yaml's
// ARGUS_BOOTSTRAP_PASSWORD default, which is "change-me". This comment used
// to claim it did, and that claim went stale on 2026-09-16 (commit 3aa8969)
// when the compose default changed. Nothing failed locally — a developer's
// database is bootstrapped once, long before, so the compose default is not
// consulted again — but every nightly CI run starts from an empty volume,
// bootstrapped "change-me", and globalSetup has failed at login ever since.
//
// So do not "fix" this back to the compose default: CI no longer depends on
// either default. .github/workflows/e2e.yml sets ARGUS_BOOTSTRAP_PASSWORD and
// ARGUS_E2E_PASSWORD together, from one place, precisely so these two files
// cannot drift apart again. This literal is the local-developer convenience,
// and ARGUS_E2E_PASSWORD overrides it for a stack whose admin password has
// since been changed (which is every long-lived dev instance).
export const ADMIN_EMAIL = process.env.ARGUS_E2E_EMAIL ?? 'admin@localhost'
export const ADMIN_PASSWORD = process.env.ARGUS_E2E_PASSWORD ?? 'dev-admin-password-123'

async function apiRequest(baseURL: string, path: string, init: RequestInit & { accessToken?: string } = {}) {
  const headers: Record<string, string> = { Accept: 'application/json', ...(init.headers as Record<string, string>) }
  if (init.accessToken) headers.Authorization = `Bearer ${init.accessToken}`
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(`${baseURL}/api/v1${path}`, { ...init, headers })
  return res
}

export async function apiLogin(
  baseURL: string,
  email: string,
  password: string,
): Promise<{ accessToken: string }> {
  const res = await apiRequest(baseURL, '/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    throw new Error(
      `e2e setup: login as ${email} against ${baseURL} failed (HTTP ${res.status}). ` +
        `Set ARGUS_E2E_EMAIL/ARGUS_E2E_PASSWORD if this dev stack's bootstrap admin ` +
        `credential differs from RUNBOOK.md's documented default.`,
    )
  }
  const body = (await res.json()) as { accessToken: string }
  return body
}

// Idempotent: a 404 (no demo data exists yet) is the expected steady state,
// not a failure — every other non-2xx status is, and is surfaced loudly
// rather than silently swallowed, since a swallowed 401/500 here would leave
// every later test running against whatever demo data happened to already
// exist instead of the fixture this suite actually asserts on.
export async function clearDemoData(baseURL: string, accessToken: string): Promise<void> {
  const res = await apiRequest(baseURL, '/demo-data', { method: 'DELETE', accessToken })
  if (!res.ok && res.status !== 404) {
    throw new Error(`e2e setup: DELETE /api/v1/demo-data failed (HTTP ${res.status}): ${await res.text()}`)
  }
}

export async function seedDemoData(baseURL: string, accessToken: string): Promise<{ clusterId: string; incidentCount: number }> {
  const res = await apiRequest(baseURL, '/demo-data', { method: 'POST', accessToken })
  if (!res.ok) {
    throw new Error(`e2e setup: POST /api/v1/demo-data failed (HTTP ${res.status}): ${await res.text()}`)
  }
  return (await res.json()) as { clusterId: string; incidentCount: number }
}

// --- test-only cluster fixture (bulk-actions.spec.ts) ---------------------
//
// Two REAL clusters, created through the product's own enrollment API
// (POST /clusters/enrollment-tokens -> POST /clusters/enroll), for the one
// spec that needs more than one decommissionable cluster to select.
//
// NOT seeded through the demo-data endpoint, deliberately: demo_data.go's
// `demoClusterFingerprint` is a sentinel for "the ONE demo cluster a tenant
// may have" and its teardown deletes by exactly that fingerprint, so
// teaching it to seed extra clusters would rework a documented invariant and
// change what every demo install shows — a product decision, not a test
// edit. Enrolling throwaway clusters instead needs neither: it uses the same
// two endpoints `argusctl cluster add` uses, and nothing about the demo
// fixture changes.
//
// A cluster enrolled this way sits in PendingApproval (handleEnroll) and
// stays there — it is never accepted, so no certificate is ever issued for
// the CSR below and no agent ever connects. PendingApproval is a real,
// non-terminal state, which is exactly what "decommissionable" means to both
// halves of the flow under test: ClustersPage's `isBulkDecommissionEligible`
// (not Archived/Rejected) and handleDecommissionCluster (409s only on those
// same two). Disconnected is NOT reachable for a fixture: health.go's sweep
// only demotes clusters already in Active/Degraded, and reaching Active needs
// a real mTLS tunnel and a real heartbeat, i.e. a real agent.

// A throwaway PKCS#10 request, required by handleEnroll's parseCSR (it must
// parse and its self-signature must verify; nothing else about it is read at
// enrollment time). Generated once with
//   openssl req -new -newkey ed25519 -nodes -keyout /dev/null \
//     -subj "/CN=argus-e2e-bulk-fixture" -out csr.pem
// — the private key went to /dev/null at generation and no certificate is
// ever issued against it, so this is a public key and a signature over a
// name, carrying nothing to keep secret. Inlined rather than shelled out to
// openssl per run so the suite depends on nothing outside Node.
const FIXTURE_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIGgMFQCAQAwITEfMB0GA1UEAwwWYXJndXMtZTJlLWJ1bGstZml4dHVyZTAqMAUG
AytlcAMhAPIQmp4u3HrPatO6EWkwjk+Lr/V4+DVpmb7zacNbLnlGoAAwBQYDK2Vw
A0EAa7RlrjNEonH+Y36Rdrajqoxj42qZM8rNxAFdSIbm5vPhX7cdEQk+FHEmzF6m
+T5el1ZheE1umfA70TuYkgMIBw==
-----END CERTIFICATE REQUEST-----
`

// Every fixture cluster's display name starts with this, and
// archiveFixtureClusters refuses to touch anything that does not — the demo
// cluster ("Demo Cluster (sample data)"), and any real cluster a developer
// has enrolled on the stack this suite is pointed at, are unreachable from
// the sweep by construction.
export const FIXTURE_CLUSTER_PREFIX = 'e2e-bulk-fixture-'

export async function enrollFixtureCluster(
  baseURL: string,
  accessToken: string,
  displayName: string,
): Promise<string> {
  if (!displayName.startsWith(FIXTURE_CLUSTER_PREFIX)) {
    throw new Error(`e2e fixture: cluster display name must start with ${FIXTURE_CLUSTER_PREFIX} (got ${displayName})`)
  }
  // TTL class A: 15 minutes, single redemption (lld/03-agent-protocol.md §2's
  // shortest-lived class) — one token per fixture cluster, used seconds
  // later, rather than a longer-lived multi-redemption class C token.
  const tokenRes = await apiRequest(baseURL, '/clusters/enrollment-tokens', {
    method: 'POST',
    accessToken,
    body: JSON.stringify({ ttlClass: 'A', maxRedemptions: 1, scopeHint: {} }),
  })
  if (!tokenRes.ok) {
    throw new Error(`e2e fixture: POST /clusters/enrollment-tokens failed (HTTP ${tokenRes.status}): ${await tokenRes.text()}`)
  }
  const { token } = (await tokenRes.json()) as { token: string }

  // The fingerprint is what clusters_fingerprint_active_idx enforces
  // uniqueness on among non-archived clusters, so it is derived from the
  // (per-run unique) display name: re-running the suite never collides with
  // its own archived leftovers, and no fixture can ever collide with
  // demoClusterFingerprint.
  const enrollRes = await apiRequest(baseURL, '/clusters/enroll', {
    method: 'POST',
    body: JSON.stringify({
      token,
      csrPem: FIXTURE_CSR_PEM,
      clusterFingerprint: `argus-${displayName}-fingerprint`,
      displayName,
    }),
  })
  if (!enrollRes.ok) {
    throw new Error(`e2e fixture: POST /clusters/enroll failed (HTTP ${enrollRes.status}): ${await enrollRes.text()}`)
  }
  const { clusterId } = (await enrollRes.json()) as { clusterId: string }
  return clusterId
}

// Teardown: decommissions every LIVE cluster whose display name starts with
// `prefix`, which must itself be a fixture prefix. Swept by name rather than
// by the ids this run created, so a run killed before its own teardown does
// not leave a stray fixture cluster in the fleet forever — the next run's
// teardown collects it.
//
// Decommission is the only offboarding the API has (there is no DELETE
// /clusters/{id}), so what this leaves behind is an Archived row: invisible
// to GET /api/v1/clusters and to every screen but the Clusters page's
// "Retired" view, where a locally-run suite accumulates one pair per run.
// CI never sees that — `docker compose down -v` wipes the volume every night.
export async function archiveFixtureClusters(
  baseURL: string,
  accessToken: string,
  prefix: string,
): Promise<number> {
  if (!prefix.startsWith(FIXTURE_CLUSTER_PREFIX)) {
    throw new Error(`e2e fixture: refusing to sweep clusters by prefix ${prefix} — must start with ${FIXTURE_CLUSTER_PREFIX}`)
  }
  const listRes = await apiRequest(baseURL, '/clusters', { accessToken })
  if (!listRes.ok) {
    throw new Error(`e2e fixture: GET /clusters failed (HTTP ${listRes.status}): ${await listRes.text()}`)
  }
  const { clusters } = (await listRes.json()) as { clusters: Array<{ id: string; displayName: string }> }

  let archived = 0
  for (const cluster of clusters) {
    if (!cluster.displayName.startsWith(prefix)) continue
    const res = await apiRequest(baseURL, `/clusters/${cluster.id}/decommission`, { method: 'POST', accessToken })
    // 409 is "already in a terminal state" — the ordinary case when the test
    // under test did its job and decommissioned the cluster itself.
    if (!res.ok && res.status !== 409) {
      throw new Error(
        `e2e fixture: POST /clusters/${cluster.id}/decommission failed (HTTP ${res.status}): ${await res.text()}`,
      )
    }
    if (res.ok) archived++
  }
  return archived
}
