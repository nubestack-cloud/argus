// enroll.go drives the exact same login -> enrollment-token -> enroll ->
// accept -> poll-for-cert REST sequence scripts/smoke-test.sh's §2/§6
// already exercise by hand with curl/openssl/python3 — reimplemented here
// in Go so this harness is one self-contained binary, not a shell script
// shelling out to a second language for JSON handling. Nothing here is a
// new capability; it is the established flow, ported.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

// resolveAdminPassword mirrors smoke-test.sh's own three-tier fallback
// exactly: an explicit override, then a scrape of `docker compose logs
// hub-api` for bootstrap's one-time-printed password, then the fixed
// dev-profile default docker-compose.yaml pins ARGUS_BOOTSTRAP_PASSWORD to.
func resolveAdminPassword(explicit, composeFile string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	out, err := exec.Command("docker", "compose", "-f", composeFile, "logs", "hub-api").CombinedOutput()
	if err == nil {
		re := regexp.MustCompile(`password: (\S+)`)
		if m := re.FindStringSubmatch(string(out)); m != nil {
			return m[1], nil
		}
	}

	return "dev-admin-password-123", nil
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
}

func (c *apiClient) login(email, password string) error {
	var resp loginResponse
	_, err := c.post("/api/v1/auth/login", map[string]string{"email": email, "password": password}, &resp)
	if err != nil {
		return fmt.Errorf("login as %s: %w", email, err)
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("login as %s: no accessToken in response", email)
	}
	c.accessToken = resp.AccessToken
	// Remembered so apiClient.doWith can re-authenticate on an expired token
	// without the caller having to thread credentials through every call —
	// see the fields' own comment for what that costs a run otherwise.
	c.email, c.password = email, password
	return nil
}

type enrollmentTokenResponse struct {
	Token string `json:"token"`
}

func (c *apiClient) createEnrollmentToken() (string, error) {
	var resp enrollmentTokenResponse
	_, err := c.post("/api/v1/clusters/enrollment-tokens", map[string]string{"ttlClass": "B"}, &resp)
	if err != nil {
		return "", fmt.Errorf("create enrollment token: %w", err)
	}
	return resp.Token, nil
}

// generatedKey bundles a throwaway ECDSA P-256 key's CSR and PEM-encoded
// private key — the same key algorithm scripts/smoke-test.sh's
// `openssl ecparam -name prime256v1` call uses, ported to crypto/ecdsa so
// this file needs no external `openssl` binary on PATH.
type generatedKey struct {
	csrPEM string
	keyPEM []byte
}

func generateCSR(commonName string) (*generatedKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	template := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &generatedKey{csrPEM: string(csrPEM), keyPEM: keyPEM}, nil
}

type enrollResponse struct {
	ClusterID string `json:"clusterId"`
	Status    string `json:"status"`
	PollToken string `json:"pollToken"`
}

func (c *apiClient) enrollCluster(token, csrPEM, fingerprint, displayName string) (clusterID, pollToken string, err error) {
	var resp enrollResponse
	unauth := &apiClient{baseURL: c.baseURL, http: c.http} // enroll is deliberately unauthenticated
	_, err = unauth.post("/api/v1/clusters/enroll", map[string]string{
		"token":              token,
		"csrPem":             csrPEM,
		"clusterFingerprint": fingerprint,
		"displayName":        displayName,
	}, &resp)
	if err != nil {
		return "", "", fmt.Errorf("enroll cluster: %w", err)
	}
	return resp.ClusterID, resp.PollToken, nil
}

func (c *apiClient) acceptCluster(clusterID string) error {
	_, err := c.post(fmt.Sprintf("/api/v1/clusters/%s/accept", clusterID), nil, nil)
	if err != nil {
		return fmt.Errorf("accept cluster %s: %w", clusterID, err)
	}
	return nil
}

type enrollStatusResponse struct {
	Status      string `json:"status"`
	CertPem     string `json:"certPem"`
	CAPem       string `json:"caPem"`
	HubEndpoint string `json:"hubEndpoint"`
}

// pollForCert polls GET /clusters/enroll/status until the cert is issued
// (which only happens once acceptCluster has been called) or timeout
// elapses.
func (c *apiClient) pollForCert(pollToken string, timeout time.Duration) (certPEM, caPEM string, err error) {
	unauth := &apiClient{baseURL: c.baseURL, http: c.http}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var resp enrollStatusResponse
		_, err = unauth.get("/api/v1/clusters/enroll/status?pollToken="+pollToken, &resp)
		if err != nil {
			return "", "", fmt.Errorf("poll enroll status: %w", err)
		}
		switch resp.Status {
		case "issued":
			return resp.CertPem, resp.CAPem, nil
		case "rejected":
			return "", "", fmt.Errorf("enrollment was rejected")
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", "", fmt.Errorf("timed out after %s waiting for the certificate to be issued", timeout)
}

type clusterStateResponse struct {
	State string `json:"state"`
}

func (c *apiClient) waitForClusterState(clusterID, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		var resp clusterStateResponse
		if _, err := c.get("/api/v1/clusters/"+clusterID, &resp); err == nil {
			last = resp.State
			if resp.State == want {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for cluster %s to reach state %q (last seen: %q)", clusterID, want, last)
}

// putLLMSettingsFull points the hub's AI provider config at baseURL/model
// (and apiKey, if the real provider this harness was pointed at via
// -llm-base-url needs one — always "" for the in-process fake reasoner).
// Live-editable per internal/settings' own "resolved fresh per call, never
// cached" discipline (internal/llm/toolloop.go's doc comment) — the very
// next POST /analyze this harness issues sees it, no hub restart required.
func (c *apiClient) putLLMSettingsFull(baseURL, model, apiKey string) error {
	body := map[string]any{
		"llm": map[string]string{"baseUrl": baseURL, "model": model, "apiKey": apiKey},
	}
	_, err := c.put("/api/v1/admin/settings", body, nil)
	if err != nil {
		return fmt.Errorf("PUT /admin/settings: %w", err)
	}
	return nil
}

// llmSettingsView is the "llm" section of GET /api/v1/admin/settings, as
// much of it as this harness needs. Mirrors internal/api's own view struct
// by field name, not by import — same posture as the rest of this file: the
// harness talks to the hub the way a network client does.
//
// CLIBackendAvailable is the one field here that is not an admin's setting
// but a property of how the hub process was started (whether it has an MCP
// listener at all). internal/api reports it precisely because a cli provider
// can be configured correctly and still be unusable, and no client can infer
// that. The harness checks it before spending a corpus of analyze calls.
type llmSettingsView struct {
	BaseURL             string `json:"baseUrl"`
	Model               string `json:"model"`
	ProviderKind        string `json:"providerKind"`
	CLIRunnerURL        string `json:"cliRunnerUrl"`
	CLIAgent            string `json:"cliAgent"`
	CLIBackendAvailable bool   `json:"cliBackendAvailable"`
}

// getLLMSettings reads back which model the hub will actually use. Secrets
// are not in the response and are not wanted: the question is "what will
// answer the next analyze call", not "with what credential".
func (c *apiClient) getLLMSettings() (llmSettingsView, error) {
	var resp struct {
		LLM llmSettingsView `json:"llm"`
	}
	if _, err := c.get("/api/v1/admin/settings", &resp); err != nil {
		return llmSettingsView{}, fmt.Errorf("GET /admin/settings: %w", err)
	}
	return resp.LLM, nil
}
