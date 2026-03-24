package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"time"
)

// CallbackServer handles OAuth callbacks
type CallbackServer struct {
	server   *http.Server
	listener net.Listener
	codeChan chan string
	errChan  chan error
	state    string
}

// NewCallbackServer creates a new OAuth callback server
func NewCallbackServer() (*CallbackServer, error) {
	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}

	// Generate random state token for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to generate state token: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	cs := &CallbackServer{
		listener: listener,
		codeChan: make(chan string, 1),
		errChan:  make(chan error, 1),
		state:    state,
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", cs.handleCallback)

	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return cs, nil
}

// GetRedirectURL returns the callback URL
func (cs *CallbackServer) GetRedirectURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", cs.listener.Addr().(*net.TCPAddr).Port)
}

// GetState returns the CSRF state token
func (cs *CallbackServer) GetState() string {
	return cs.state
}

// Start starts the callback server
func (cs *CallbackServer) Start() error {
	go func() {
		if err := cs.server.Serve(cs.listener); err != nil && err != http.ErrServerClosed {
			cs.errChan <- err
		}
	}()
	return nil
}

// WaitForCode waits for the OAuth callback with a timeout
func (cs *CallbackServer) WaitForCode(timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case code := <-cs.codeChan:
		return code, nil
	case err := <-cs.errChan:
		return "", err
	case <-timer.C:
		return "", fmt.Errorf("timeout waiting for OAuth callback")
	}
}

// Shutdown gracefully shuts down the server
func (cs *CallbackServer) Shutdown(ctx context.Context) error {
	return cs.server.Shutdown(ctx)
}

// handleCallback handles the OAuth callback request
func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for error from OAuth provider
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		cs.errChan <- fmt.Errorf("OAuth error: %s (%s)", errMsg, errDesc)
		cs.renderError(w, fmt.Sprintf("OAuth Error: %s", errMsg))
		return
	}

	// Get state and code
	receivedState := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Validate state (CSRF protection)
	if receivedState != cs.state {
		cs.errChan <- fmt.Errorf("invalid state token (possible CSRF attack)")
		cs.renderError(w, "Invalid state token")
		return
	}

	// Check code exists
	if code == "" {
		cs.errChan <- fmt.Errorf("no authorization code received")
		cs.renderError(w, "No authorization code received")
		return
	}

	// Send code to channel
	cs.codeChan <- code

	// Render success page
	cs.renderSuccess(w)
}

// renderSuccess renders a success page
func (cs *CallbackServer) renderSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	tmpl := template.Must(template.New("success").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
        }
        h1 {
            color: #2d3748;
            margin-top: 0;
        }
        .success-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        .message {
            color: #4a5568;
            margin-bottom: 1.5rem;
        }
        .info {
            color: #718096;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Authentication Successful!</h1>
        <p class="message">You have successfully authenticated with nokey.</p>
        <p class="info">You can close this window and return to your terminal.</p>
    </div>
</body>
</html>
`))

	_ = tmpl.Execute(w, nil)
}

// renderError renders an error page
func (cs *CallbackServer) renderError(w http.ResponseWriter, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)

	tmpl := template.Must(template.New("error").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Authentication Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
        }
        h1 {
            color: #2d3748;
            margin-top: 0;
        }
        .error-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        .message {
            color: #4a5568;
            margin-bottom: 1.5rem;
        }
        .error-details {
            background: #fed7d7;
            color: #c53030;
            padding: 1rem;
            border-radius: 5px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>Authentication Failed</h1>
        <p class="message">There was an error during authentication.</p>
        <div class="error-details">{{.}}</div>
    </div>
</body>
</html>
`))

	_ = tmpl.Execute(w, errorMsg)
}
