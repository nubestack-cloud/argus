package api

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"

	"argus/internal/logging"
	"argus/internal/tunnel"
)

// agentTunnelUpgrader accepts the agent tunnel's WebSocket. There is no
// browser on the other end and no session cookie to protect, so the Origin
// check that guards the UI's event socket does not apply: the caller is
// authenticated by the mTLS handshake that runs inside the socket, against
// the client certificate the hub issued at enrollment.
var agentTunnelUpgrader = websocket.Upgrader{
	ReadBufferSize:  32 << 10,
	WriteBufferSize: 32 << 10,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// handleAgentTunnel is GET /api/v1/agent/tunnel: the agent tunnel, carried
// over a WebSocket on the hub's ordinary HTTP(S) address so that it passes
// through the same Ingress as the UI. Unauthenticated at the HTTP layer by
// design; see agentTunnelUpgrader. Holds the request for the whole session.
func (s *Server) handleAgentTunnel(w http.ResponseWriter, r *http.Request) {
	ws, err := agentTunnelUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written the HTTP error.
		logger.WarnContext(r.Context(), "agent tunnel upgrade refused", slog.String("peer", r.RemoteAddr), logging.Err(err))
		return
	}
	s.gw.ServeTunnelConn(tunnel.NewWebSocketConn(ws))
}
