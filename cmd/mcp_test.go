package cmd

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestTruncateOutput(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		max      int
		wantLen  int
		wantTail string // expected suffix after truncation
	}{
		{
			name:    "under limit unchanged",
			data:    []byte("hello"),
			max:     100,
			wantLen: 5,
		},
		{
			name:    "exactly at limit unchanged",
			data:    []byte("hello"),
			max:     5,
			wantLen: 5,
		},
		{
			name:     "over limit truncated",
			data:     bytes.Repeat([]byte("x"), 200),
			max:      100,
			wantLen:  100,
			wantTail: "\n\n[output truncated]",
		},
		{
			name:    "nil data",
			data:    nil,
			max:     100,
			wantLen: 0,
		},
		{
			name:    "empty data",
			data:    []byte{},
			max:     100,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateOutput(tt.data, tt.max)
			if len(got) != tt.wantLen {
				t.Errorf("truncateOutput() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantTail != "" && !strings.HasSuffix(string(got), tt.wantTail) {
				t.Errorf("truncateOutput() should end with %q, got tail %q",
					tt.wantTail, string(got[len(got)-len(tt.wantTail):]))
			}
		})
	}
}

// mockRequester implements elicitationRequester for testing.
type mockRequester struct {
	result *mcp.ElicitationResult
	err    error
}

func (m *mockRequester) RequestElicitation(_ context.Context, _ mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	return m.result, m.err
}

func TestRequestApproval(t *testing.T) {
	tests := []struct {
		name    string
		result  *mcp.ElicitationResult
		err     error
		wantErr string // empty = no error expected
	}{
		{
			name: "user accepts",
			result: &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action: mcp.ElicitationResponseActionAccept,
				},
			},
		},
		{
			name: "user declines",
			result: &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action: mcp.ElicitationResponseActionDecline,
				},
			},
			wantErr: "user declined secret access",
		},
		{
			name: "user cancels",
			result: &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action: mcp.ElicitationResponseActionCancel,
				},
			},
			wantErr: "user cancelled secret access",
		},
		{
			name:    "elicitation not supported",
			err:     server.ErrElicitationNotSupported,
			wantErr: "client does not support elicitation",
		},
		{
			name:    "no active session",
			err:     server.ErrNoActiveSession,
			wantErr: "no active MCP session",
		},
		{
			name:    "other error",
			err:     fmt.Errorf("transport broken"),
			wantErr: "approval request failed: transport broken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockRequester{result: tt.result, err: tt.err}
			err := requestApproval(context.Background(), mock, "gh", []string{"GITHUB_TOKEN"})

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
