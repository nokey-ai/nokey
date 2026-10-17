package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func handle(t *testing.T, s *server.MCPServer, msg string) string {
	t.Helper()
	out, err := json.Marshal(s.HandleMessage(context.Background(), json.RawMessage(msg)))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return string(out)
}

func TestNewMCPServer_SendsInstructions(t *testing.T) {
	s := newMCPServer()
	resp := handle(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`)

	var parsed struct {
		Result struct {
			Instructions string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("unmarshal %s: %v", resp, err)
	}
	for _, want := range []string{"list_secrets", "exec_with_secrets", "mint_token", "nokey:integration:github"} {
		if !strings.Contains(parsed.Result.Instructions, want) {
			t.Errorf("instructions do not mention %q: %q", want, parsed.Result.Instructions)
		}
	}
}

// A panicking handler must come back as an error, not take down the
// server and every session on it.
func TestNewMCPServer_RecoversFromPanics(t *testing.T) {
	s := newMCPServer()
	s.AddTool(mcp.NewTool("boom"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("boom")
	})

	resp := handle(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom","arguments":{}}}`)
	if !strings.Contains(resp, "panic recovered") {
		t.Errorf("response = %s, want a recovered-panic error", resp)
	}
}
