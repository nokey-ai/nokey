package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/mcpserver"
	"github.com/nokey-ai/nokey/internal/policy"
)

// mcpMessage is any JSON-RPC message: a request from either side, or a
// response.
type mcpMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// execAsOwnClient runs one exec_with_secrets call through `nokey mcp
// serve`'s server and approval wiring, with the test as the MCP client.
// The test accepts every elicitation prompt, as an agent that launched its
// own server would. It returns the tool result and the number of prompts.
func execAsOwnClient(t *testing.T) (result string, isError bool, prompts int) {
	t.Helper()
	store, _ := newTestStore()
	_ = store.Set("TEST_KEY", "test-value")
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false

	h := mcpserver.New(mcpserver.Deps{
		GetStore:           func() (mcpserver.SecretStore, error) { return store, nil },
		GetPolicy:          func() *policy.Policy { return nil },
		Config:             c,
		ApprovalFn:         mcpApprovalFn,
		RememberApprovalFn: mcpRememberApprovalFn,
		GetConfigDir:       func() (string, error) { return t.TempDir(), nil },
	})
	s := newMCPServer()
	h.RegisterTools(s)

	serverR, clientW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	clientR, serverW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		serverR.Close()
		clientW.Close()
		clientR.Close()
		serverW.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	go func() { _ = server.NewStdioServer(s).Listen(ctx, serverR, serverW) }()

	reader := bufio.NewReader(clientR)
	send := func(msg map[string]any) {
		t.Helper()
		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clientW.Write(append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	read := func() mcpMessage {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var msg mcpMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		return msg
	}

	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18",
		"clientInfo":      map[string]any{"name": "self", "version": "0"},
		"capabilities":    map[string]any{"elicitation": map[string]any{}},
	}})
	if msg := read(); msg.Error != nil {
		t.Fatalf("initialize: %s", msg.Error)
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name":      "exec_with_secrets",
		"arguments": map[string]any{"command": "echo", "args": []string{"${{NOKEY:TEST_KEY}}"}},
	}})
	for {
		msg := read()
		if msg.Method == "elicitation/create" {
			prompts++
			send(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"action": "accept", "content": map[string]any{}}})
			continue
		}
		if msg.Method != "" {
			continue // a notification
		}
		if msg.Error != nil {
			t.Fatalf("tools/call: %s", msg.Error)
		}
		var res struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msg.Result, &res); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		var text []string
		for _, c := range res.Content {
			text = append(text, c.Text)
		}
		return strings.Join(text, "\n"), res.IsError, prompts
	}
}

// An agent that starts its own `nokey mcp serve` is the MCP client, so it
// can accept its own elicitation prompts. That Accept must not be enough.
func TestMCPApproval_ClientAcceptNeedsPresence(t *testing.T) {
	reasons := withPresence(t, errors.New("not confirmed: cancelled"))

	result, isError, prompts := execAsOwnClient(t)
	if prompts != 1 {
		t.Errorf("elicitation prompts = %d, want 1", prompts)
	}
	if !isError || !strings.Contains(result, "not confirmed") {
		t.Errorf("result = %q (isError %v), want a refusal from the presence check", result, isError)
	}
	if strings.Contains(result, "test-value") || strings.Contains(result, "REDACTED") {
		t.Errorf("the command ran: %q", result)
	}
	if len(*reasons) != 1 || !strings.Contains((*reasons)[0], "TEST_KEY") {
		t.Errorf("presence reasons = %q, want one naming TEST_KEY", *reasons)
	}
}

func TestMCPApproval_PresenceConfirmed(t *testing.T) {
	withPresence(t, nil)

	result, isError, _ := execAsOwnClient(t)
	if isError || !strings.Contains(result, "[REDACTED:TEST_KEY]") {
		t.Errorf("result = %q (isError %v), want the redacted command output", result, isError)
	}
}

// With no presence dialog (another OS, no GUI session) the MCP server has
// no terminal for a PIN, so approval fails closed.
func TestMCPApproval_NoPresenceFailsClosed(t *testing.T) {
	// TestMain's default stub reports no presence check.
	result, isError, _ := execAsOwnClient(t)
	if !isError || !strings.Contains(result, "Touch ID") {
		t.Errorf("result = %q (isError %v), want a refusal naming the missing presence check", result, isError)
	}
}
