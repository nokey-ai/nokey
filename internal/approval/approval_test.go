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

func TestRequestWithDetail_NoDetail(t *testing.T) {
	tests := []struct {
		name    string
		result  *mcp.ElicitationResult
		err     error
		wantErr string // empty = no error expected
	}{
		{
			// The Accept button is the approval; no form field is needed.
			name: "user accepts",
			result: &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action: mcp.ElicitationResponseActionAccept,
				},
			},
		},
		{
			name: "user accepts with unrelated content",
			result: &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action:  mcp.ElicitationResponseActionAccept,
					Content: map[string]any{"other": true},
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
			err := RequestWithDetail(context.Background(), mock, "gh", []string{"GITHUB_TOKEN"}, "")

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
	msg     string
	schema  map[string]any
	content any // what the "user" submits with Accept
}

func (c *capturingRequester) RequestElicitation(_ context.Context, req mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	c.msg = req.Params.Message
	c.schema, _ = req.Params.RequestedSchema.(map[string]any)
	return &mcp.ElicitationResult{
		ElicitationResponse: mcp.ElicitationResponse{
			Action:  mcp.ElicitationResponseActionAccept,
			Content: c.content,
		},
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
	if !strings.HasSuffix(c.msg, "Accept to approve, Decline to deny.") {
		t.Errorf("prompt %q should end by saying what the buttons do", c.msg)
	}
}

// An empty detail adds no extra line to the prompt.
func TestRequestWithDetail_EmptyDetailPrompt(t *testing.T) {
	c := &capturingRequester{}
	if err := RequestWithDetail(context.Background(), c, "gh", []string{"A", "B"}, ""); err != nil {
		t.Fatalf("RequestWithDetail: %v", err)
	}
	want := "nokey: \"gh\" wants to access secret(s): A, B\n\nAccept to approve, Decline to deny."
	if c.msg != want {
		t.Errorf("prompt = %q, want %q", c.msg, want)
	}
}

// The plain prompt has no form fields, so approving is one click on Accept.
func TestRequestWithDetail_SchemaHasNoFields(t *testing.T) {
	c := &capturingRequester{}
	if err := RequestWithDetail(context.Background(), c, "gh", []string{"A"}, ""); err != nil {
		t.Fatalf("RequestWithDetail: %v", err)
	}
	props, _ := c.schema["properties"].(map[string]any)
	if len(props) != 0 {
		t.Errorf("properties = %v, want none", c.schema["properties"])
	}
	if _, ok := c.schema["required"]; ok {
		t.Errorf("required = %v, want no required fields", c.schema["required"])
	}
}

// The rememberable prompt offers one optional checkbox, off by default.
func TestRequestRememberable_Schema(t *testing.T) {
	c := &capturingRequester{}
	if _, err := RequestRememberable(context.Background(), c, "curl", []string{"A"}, ""); err != nil {
		t.Fatalf("RequestRememberable: %v", err)
	}
	props, _ := c.schema["properties"].(map[string]any)
	if len(props) != 1 {
		t.Fatalf("properties = %v, want only remember", props)
	}
	remember, _ := props["remember"].(map[string]any)
	if remember["type"] != "boolean" || remember["default"] != false {
		t.Errorf("remember = %v, want an optional boolean defaulting to false", remember)
	}
	if !strings.Contains(remember["description"].(string), `"curl"`) {
		t.Errorf("description %q should name the command", remember["description"])
	}
	if _, ok := c.schema["required"]; ok {
		t.Errorf("remember must be optional, got required = %v", c.schema["required"])
	}
}

func TestRequestRememberable_Answers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content any
		want    bool
	}{
		{"accept without content", nil, false},
		{"accept with box unticked", map[string]any{"remember": false}, false},
		{"accept with box ticked", map[string]any{"remember": true}, true},
		{"non-boolean remember", map[string]any{"remember": "true"}, false},
		{"non-object content", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &capturingRequester{content: tc.content}
			got, err := RequestRememberable(context.Background(), c, "curl", []string{"A"}, "")
			if err != nil {
				t.Fatalf("an Accept must approve: %v", err)
			}
			if got != tc.want {
				t.Errorf("remember = %v, want %v", got, tc.want)
			}
		})
	}
}

// A plain prompt never reports remember, even if a client sends it.
func TestRequestWithDetail_IgnoresRemember(t *testing.T) {
	c := &capturingRequester{content: map[string]any{"remember": true}}
	remember, err := request(context.Background(), c, "gh", []string{"A"}, "", false)
	if err != nil || remember {
		t.Errorf("got (%v, %v), want (false, nil)", remember, err)
	}
}

func TestRequestRememberable_Decline(t *testing.T) {
	mock := &mockRequester{result: &mcp.ElicitationResult{
		ElicitationResponse: mcp.ElicitationResponse{
			Action:  mcp.ElicitationResponseActionDecline,
			Content: map[string]any{"remember": true},
		},
	}}
	remember, err := RequestRememberable(context.Background(), mock, "curl", []string{"A"}, "")
	if err == nil || remember {
		t.Errorf("got (%v, %v), want a decline error and no remember", remember, err)
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
	// Capped output must say how much is hidden: args past the cut are
	// still run, so the user needs to know they exist.
	long := FormatArgs([]string{strings.Repeat("a", 600), "--hidden", "x"})
	if len(long) > maxDetailArgsBytes+64 {
		t.Errorf("FormatArgs not capped: %d bytes", len(long))
	}
	if !strings.HasSuffix(long, "… (+111 more bytes; 3 args in all)") {
		t.Errorf("capped args should say what was cut, got tail %q", long[len(long)-40:])
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

func TestFormatEnvAndStdin(t *testing.T) {
	if FormatEnv(nil) != "" || FormatStdin("") != "" {
		t.Error("empty env and stdin should render as nothing")
	}
	if got := FormatEnv(map[string]string{"B": "2", "A": "x\ny"}); got != `env: A="x\ny" B="2"` {
		t.Errorf("FormatEnv = %q", got)
	}
	got := FormatStdin("echo hi\n" + strings.Repeat("z", 200))
	if !strings.HasPrefix(got, `stdin: 208 bytes, starting "echo hi\n`) || strings.Contains(got, strings.Repeat("z", 100)) {
		t.Errorf("FormatStdin = %q, want the size and a short preview", got)
	}
}
