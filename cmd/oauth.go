package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// runOAuthFlow starts a local callback server, opens the browser for OAuth,
// and waits for the server to redirect back with a JWT token.
func runOAuthFlow(apiBaseURL string) (string, error) {
	// Bind to a random available port on localhost
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// Generate CSRF state
	stateBytes := make([]byte, 24)
	if _, err := rand.Read(stateBytes); err != nil {
		listener.Close()
		return "", fmt.Errorf("generate state: %w", err)
	}
	state := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(stateBytes)

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "State mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("OAuth state mismatch")
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "No token received", http.StatusBadRequest)
			errCh <- fmt.Errorf("no token in OAuth callback")
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="text-align:center"><h2>Login successful!</h2><p>You can close this window and return to your terminal.</p></div>
</body></html>`)

		tokenCh <- token
	})

	server := &http.Server{Handler: mux}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Build the OAuth URL — strip /api/v1 from the base URL to get the root
	authBase := strings.TrimSuffix(apiBaseURL, "/api/v1")
	authBase = strings.TrimRight(authBase, "/")
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	oauthURL := fmt.Sprintf("%s/auth/oauth/google?cli_callback=%s&cli_state=%s", authBase, callbackURL, state)

	fmt.Println("Opening browser for authentication...")
	if err := openBrowser(oauthURL); err != nil {
		fmt.Printf("\nCould not open browser automatically.\nPlease open this URL in your browser:\n\n  %s\n\n", oauthURL)
	}
	fmt.Println("Waiting for authentication...")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	defer server.Shutdown(context.Background())

	select {
	case token := <-tokenCh:
		return token, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("authentication timed out after 2 minutes")
	}
}

// openBrowser opens the specified URL in the default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}
