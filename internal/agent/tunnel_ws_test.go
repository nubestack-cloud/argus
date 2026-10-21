package agent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"argus/internal/tunnel"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test hub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns PEM cert and key for a leaf signed by the CA.
func (ca testCA) issue(t *testing.T, serial int64, cn string, dns []string, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// TestTunnelOverWebSocket runs the agent's own dial path against an HTTPS
// server standing in for an Ingress in front of the hub: the WebSocket
// upgrade, then the mTLS handshake inside it, then one message each way.
func TestTunnelOverWebSocket(t *testing.T) {
	hubCA := newTestCA(t)
	serverCertPEM, serverKeyPEM := hubCA.issue(t, 2, "gateway", []string{tunnel.GatewayServerName}, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	clients.AddCert(hubCA.cert)
	gatewayTLS := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients, MinVersion: tls.VersionTLS12}

	upgrader := websocket.Upgrader{}
	ingress := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tunnel.WebSocketPath {
			http.NotFound(w, r)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn := tls.Server(tunnel.NewWebSocketConn(ws), gatewayTLS)
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		peer := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
		_, _ = conn.Write([]byte("hello " + peer + ", you said " + line))
	}))
	defer ingress.Close()

	// The agent trusts the Ingress's certificate through the hub CA bundle,
	// as a private-CA install would.
	caFile := filepath.Join(t.TempDir(), "ingress-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := tunnel.WebSocketEndpoint(ingress.URL)
	if err != nil || !strings.HasPrefix(endpoint, "wss://") {
		t.Fatalf("endpoint %q: %v", endpoint, err)
	}

	cfg := Config{HubCAFile: caFile}
	clientCertPEM, clientKeyPEM := hubCA.issue(t, 3, "cluster-a", nil, x509.ExtKeyUsageClientAuth)
	tlsConfig, _, err := buildTLSConfig(cfg, endpoint, clientCertPEM, clientKeyPEM, hubCA.pem)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.ServerName != tunnel.GatewayServerName {
		t.Fatalf("server name %q: the agent must verify the gateway, not the Ingress", tlsConfig.ServerName)
	}

	conn, err := dialTunnel(context.Background(), cfg, endpoint, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("heartbeat\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "hello cluster-a, you said heartbeat\n" {
		t.Fatalf("reply %q", reply)
	}

	// An agent holding a certificate from another CA is refused inside the
	// socket, whatever the Ingress let through.
	strangerCA := newTestCA(t)
	strangerCert, strangerKey := strangerCA.issue(t, 4, "intruder", nil, x509.ExtKeyUsageClientAuth)
	strangerTLS, _, err := buildTLSConfig(cfg, endpoint, strangerCert, strangerKey, hubCA.pem)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dialTunnel(context.Background(), cfg, endpoint, strangerTLS); err == nil {
		_, _ = c.Write([]byte("x\n"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := bufio.NewReader(c).ReadString('\n'); rerr == nil {
			t.Fatal("a certificate from another CA was accepted")
		}
		c.Close()
	}
}

func TestWebSocketEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://argus.example.com":       "wss://argus.example.com/api/v1/agent/tunnel",
		"https://argus.example.com/":      "wss://argus.example.com/api/v1/agent/tunnel",
		"http://10.0.0.5:30080":           "ws://10.0.0.5:30080/api/v1/agent/tunnel",
		"https://example.com/argus?x=1#y": "wss://example.com/argus/api/v1/agent/tunnel",
	} {
		if got, err := tunnel.WebSocketEndpoint(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"argus.example.com", "ftp://x", "https://"} {
		if _, err := tunnel.WebSocketEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
