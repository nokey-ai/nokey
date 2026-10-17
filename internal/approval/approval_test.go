package approval

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

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

type capturingRequester struct {
	msg string
}

func (c *capturingRequester) RequestElicitation(_ context.Context, req mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	c.msg = req.Params.Message
	return &mcp.ElicitationResult{
		ElicitationResponse: mcp.ElicitationResponse{Action: mcp.ElicitationResponseActionAccept},
	}, nil
}

func TestRequestWithDetail_ShowsDetail(t *testing.T) {
	c := &capturingRequester{}
	if err := RequestWithDetail(context.Background(), c, "curl", []string{"K"}, "args: \"https://example.com\""); err != nil {
		t.Fatalf("RequestWithDetail: %v", err)
	}
	if !strings.Contains(c.msg, `args: "https://example.com"`) {
		t.Errorf("prompt %q does not show the detail", c.msg)
	}
	if !strings.HasSuffix(c.msg, "Do you approve?") {
		t.Errorf("prompt %q should still end with the question", c.msg)
	}
}

// Request must keep its exact prompt so existing callers see no change.
func TestRequest_UnchangedPrompt(t *testing.T) {
	c := &capturingRequester{}
	if err := Request(context.Background(), c, "gh", []string{"A", "B"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	want := "nokey: \"gh\" wants to access secret(s): A, B\n\nDo you approve?"
	if c.msg != want {
		t.Errorf("prompt = %q, want %q", c.msg, want)
	}
}

func TestFormatArgs(t *testing.T) {
	if got := FormatArgs(nil); got != "" {
		t.Errorf("FormatArgs(nil) = %q, want empty", got)
	}
	got := FormatArgs([]string{"-H", "X: ${{NOKEY:K}}", "line\nbreak"})
	want := `args: "-H" "X: ${{NOKEY:K}}" "line\nbreak"`
	if got != want {
		t.Errorf("FormatArgs = %q, want %q", got, want)
	}
	long := FormatArgs([]string{strings.Repeat("a", 2000)})
	if len(long) > maxDetailArgsBytes+len(" …(truncated)") {
		t.Errorf("FormatArgs not capped: %d bytes", len(long))
	}
	if !strings.HasSuffix(long, "…(truncated)") {
		t.Errorf("capped args should say so, got tail %q", long[len(long)-20:])
	}
}

func TestQuote(t *testing.T) {
	if got := Quote("a\nb"); got != `"a\nb"` {
		t.Errorf("Quote = %q, want %q", got, `"a\nb"`)
	}
	long := Quote(strings.Repeat("é", 500))
	if !strings.HasSuffix(long, "…(truncated)") || len(long) > maxDetailValueBytes+len(` "…(truncated)`)+2 {
		t.Errorf("Quote not capped: %d bytes, tail %q", len(long), long[len(long)-20:])
	}
	if !utf8.ValidString(long) {
		t.Error("Quote split a rune")
	}
}
