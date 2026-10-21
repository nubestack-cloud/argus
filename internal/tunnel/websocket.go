package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// The tunnel can run over a WebSocket on the hub's ordinary HTTPS address, so
// an agent needs nothing but the URL it enrolled through: the same Ingress,
// the same certificate, no second port. The mTLS session is unchanged and runs
// INSIDE the WebSocket, so the hub still identifies a cluster by the client
// certificate it issued, and the agent still pins the hub's CA. Whatever
// terminates TLS in front of the hub (an Ingress, a load balancer) only ever
// relays opaque binary frames.

// WebSocketPath is where the hub's API serves the tunnel.
const WebSocketPath = "/api/v1/agent/tunnel"

// GatewayServerName is a name every gateway certificate carries. An agent
// tunnelling through a WebSocket verifies the hub against it, because the URL
// it dialled names the Ingress, not the gateway; the pinned hub CA is what
// makes the name trustworthy.
const GatewayServerName = "argus-hub-gateway"

// IsWebSocketEndpoint reports whether a tunnel endpoint is a ws:// or wss://
// URL rather than a host:port for a direct TLS connection.
func IsWebSocketEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "wss://") || strings.HasPrefix(endpoint, "ws://")
}

// WebSocketEndpoint turns the hub's public API URL into its tunnel URL:
// https://argus.example.com becomes wss://argus.example.com/api/v1/agent/tunnel.
func WebSocketEndpoint(apiURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("the hub API URL %q must start with https:// or http://", apiURL)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the hub API URL %q has no host", apiURL)
	}
	u.Path = strings.TrimRight(u.Path, "/") + WebSocketPath
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// wsConn presents a WebSocket as a byte stream, so a TLS session can run over
// it. Each Write is one binary message; Read drains messages in order.
type wsConn struct {
	ws *websocket.Conn

	rmu sync.Mutex
	r   io.Reader

	wmu sync.Mutex
}

// NewWebSocketConn wraps an established WebSocket as a net.Conn.
func NewWebSocketConn(ws *websocket.Conn) net.Conn { return &wsConn{ws: ws} }

func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.r == nil {
			kind, r, err := c.ws.NextReader()
			if err != nil {
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) {
					return 0, io.EOF
				}
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if err == io.EOF {
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close says goodbye and closes the socket. WriteControl may run alongside a
// Write, so a Write stalled on a dead peer cannot hold Close up.
func (c *wsConn) Close() error {
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	return errors.Join(c.ws.SetReadDeadline(t), c.ws.SetWriteDeadline(t))
}
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
