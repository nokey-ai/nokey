package approval

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type mockRequester struct {
	result *mcp.ElicitationResult
	err    error
}

func (m *mockRequester) RequestElicitation(_ context.Context, _ mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	return m.result, m.err
}

func TestRequest(t *testing.T) {
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
			err := Request(context.Background(), mock, "gh", []string{"GITHUB_TOKEN"})

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
