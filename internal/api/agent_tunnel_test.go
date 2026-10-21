package api

import (
	"os"
	"strings"
	"testing"

	"argus/internal/tunnel"
)

// The route is registered with a literal (the route-coverage test reads it
// from source); it must be the path agents dial.
func TestAgentTunnelRouteIsTheTunnelPath(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"GET `+tunnel.WebSocketPath+`"`) {
		t.Fatalf("server.go does not register GET %s", tunnel.WebSocketPath)
	}
}
