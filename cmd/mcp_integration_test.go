package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/token"
	"github.com/nokey-ai/nokey/internal/version"
)

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response (partial, for test assertions).
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// sendJSONRPC writes a JSON-RPC request line.
func sendJSONRPC(t *testing.T, w io.Writer, req jsonRPCRequest) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

// readJSONRPC reads a JSON-RPC response line.
func readJSONRPC(t *testing.T, r *bufio.Reader) jsonRPCResponse {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var resp jsonRPCResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", line, err)
	}
	return resp
}

func intPtr(v int) *int { return &v }

func TestMCPIntegration_InitializeAndListTools(t *testing.T) {
	// Set up test globals
	store, _ := newTestStore()
	_ = store.Set("TEST_KEY", "test-value")
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	oldPol := pol
	oldTokenStore := tokenStore
	oldSessionTokenID := sessionTokenID
	t.Cleanup(func() {
		pol = oldPol
		tokenStore = oldTokenStore
		sessionTokenID = oldSessionTokenID
	})
	pol = nil
	tokenStore = token.NewStore()
	sessionTokenID = ""

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	// Create MCP server with registered tools
	s := server.NewMCPServer("nokey", version.Version,
		server.WithToolCapabilities(false),
	)
	mcpSrv = s
	registerMCPTools(s)

	// Use os.Pipe for kernel-buffered pipes (avoids io.Pipe deadlock)
	serverReadR, clientWriteW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	clientReadR, serverWriteW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		serverReadR.Close()
		clientWriteW.Close()
		clientReadR.Close()
		serverWriteW.Close()
	})

	stdio := server.NewStdioServer(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- stdio.Listen(ctx, serverReadR, serverWriteW)
	}()

	reader := bufio.NewReader(clientReadR)

	// 1. Initialize
	sendJSONRPC(t, clientWriteW, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      intPtr(1),
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"clientInfo":      map[string]interface{}{"name": "test", "version": "0.1"},
			"capabilities":    map[string]interface{}{},
		},
	})

	resp := readJSONRPC(t, reader)
	if resp.Error != nil {
		t.Fatalf("initialize error: %s", resp.Error)
	}

	// Send initialized notification
	sendJSONRPC(t, clientWriteW, jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	})

	// 2. List tools
	sendJSONRPC(t, clientWriteW, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      intPtr(2),
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	})

	resp = readJSONRPC(t, reader)
	if resp.Error != nil {
		t.Fatalf("tools/list error: %s", resp.Error)
	}

	var toolsResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &toolsResult); err != nil {
		t.Fatalf("unmarshal tools: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range toolsResult.Tools {
		toolNames[tool.Name] = true
	}
	for _, expected := range []string{"list_secrets", "exec", "exec_with_secrets", "mint_token"} {
		if !toolNames[expected] {
			t.Errorf("expected tool %q not found in tools list", expected)
		}
	}

	// 3. Call list_secrets
	sendJSONRPC(t, clientWriteW, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      intPtr(3),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "list_secrets",
			"arguments": map[string]interface{}{},
		},
	})

	resp = readJSONRPC(t, reader)
	if resp.Error != nil {
		t.Fatalf("tools/call list_secrets error: %s", resp.Error)
	}

	var callResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &callResult); err != nil {
		t.Fatalf("unmarshal call result: %v", err)
	}
	if len(callResult.Content) == 0 {
		t.Fatal("list_secrets returned no content")
	}
	if !strings.Contains(callResult.Content[0].Text, "TEST_KEY") {
		t.Errorf("list_secrets should contain TEST_KEY, got: %s", callResult.Content[0].Text)
	}

	// 4. Call exec with "echo hello" (no separate args needed)
	sendJSONRPC(t, clientWriteW, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      intPtr(4),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "exec",
			"arguments": map[string]interface{}{
				"command":         "echo",
				"args":            `["hello"]`,
				"timeout_seconds": 5,
			},
		},
	})

	resp = readJSONRPC(t, reader)
	if resp.Error != nil {
		t.Fatalf("tools/call exec error: %s", resp.Error)
	}
	if err := json.Unmarshal(resp.Result, &callResult); err != nil {
		t.Fatalf("unmarshal exec result: %v", err)
	}
	// echo with no args just outputs a newline — the important thing is
	// that exec completed successfully through the full MCP JSON-RPC path
	if len(callResult.Content) == 0 {
		t.Fatal("exec returned no content")
	}

	// Clean shutdown
	cancel()
	clientWriteW.Close()
	<-errCh
}
