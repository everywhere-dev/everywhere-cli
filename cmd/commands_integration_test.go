package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

type capturedRequest struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
}

type requestRecorder struct {
	mu       sync.Mutex
	requests []capturedRequest
}

func (r *requestRecorder) add(req capturedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *requestRecorder) all() []capturedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capturedRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

func (r *requestRecorder) find(method, path string) []capturedRequest {
	all := r.all()
	out := make([]capturedRequest, 0, len(all))
	for _, req := range all {
		if req.Method == method && req.Path == path {
			out = append(out, req)
		}
	}
	return out
}

func startMockAPIServer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*httptest.Server, *requestRecorder) {
	t.Helper()
	recorder := &requestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /api/v1 prefix that GetAPIEndpoint() adds
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v1")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()

		recorder.add(capturedRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Header:   r.Header.Clone(),
			Body:     body,
		})

		r.Body = io.NopCloser(bytes.NewReader(body))
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, recorder
}

func writeJSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSONBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, string(body))
	}
	return payload
}

func setupCLIEnv(t *testing.T, apiURL, authToken string) string {
	t.Helper()
	viper.Reset()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("EVERYWHERE_API_URL", apiURL)
	t.Setenv("EVERYWHERE_AUTH_TOKEN", authToken)
	t.Setenv("EVERYWHERE_USER_EMAIL", "")
	return homeDir
}

func captureOutput(t *testing.T, fn func() error) (stdout string, stderr string, err error) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdoutR, stdoutW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("create stdout pipe: %v", pipeErr)
	}
	stderrR, stderrW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("create stderr pipe: %v", pipeErr)
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW

	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
	}()

	stdoutCh := make(chan string, 1)
	stderrCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdoutR)
		stdoutCh <- string(b)
	}()
	go func() {
		b, _ := io.ReadAll(stderrR)
		stderrCh <- string(b)
	}()

	err = fn()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	stdout = <-stdoutCh
	stderr = <-stderrCh
	return stdout, stderr, err
}

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCmd()
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetArgs(args)
	return captureOutput(t, root.Execute)
}

func mustRunCLI(t *testing.T, args ...string) string {
	t.Helper()
	stdout, _, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("command failed (%s): %v\nstdout:\n%s", strings.Join(args, " "), err, stdout)
	}
	return stdout
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("expected output to contain %q\noutput:\n%s", want, got)
	}
}

func TestCLIIntegration_AuthStatus(t *testing.T) {
	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/auth/status" {
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user": map[string]any{
				"email":      "jane@example.com",
				"first_name": "Jane",
				"last_name":  "Doe",
				"tenant_id":  "tenant-1",
			},
		})
	})

	setupCLIEnv(t, server.URL, "test-token")

	stdout := mustRunCLI(t, "auth", "status")
	assertContains(t, stdout, "jane@example.com")
	assertContains(t, stdout, "Jane Doe")

	reqs := recorder.find(http.MethodGet, "/auth/status")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 auth/status call, got %d", len(reqs))
	}
	if got := reqs[0].Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("expected auth header, got %q", got)
	}
}

func TestCLIIntegration_RequiresAuthentication(t *testing.T) {
	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})

	setupCLIEnv(t, server.URL, "")
	_, _, err := runCLI(t, "apps", "list")
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected not authenticated error, got %v", err)
	}
	if len(recorder.all()) != 0 {
		t.Fatalf("expected no API requests, got %d", len(recorder.all()))
	}
}

func TestCLIIntegration_InstanceCommandFamily(t *testing.T) {
	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/instance":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg": "ok",
				"data": map[string]any{
					"items": []map[string]any{{
						"name":       "my-app",
						"status":     "running",
						"ip_address": "10.0.0.2",
						"created_at": "2026-02-28T10:00:00Z",
					}},
					"total": 1,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/instance":
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"msg": "created",
				"data": map[string]any{
					"name":       "my-app",
					"status":     "creating",
					"ip_address": "10.0.0.2",
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/start":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "started"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/stop":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "stopped"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/restart":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "restarted"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/upstream-port":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "updated"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/secrets":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "updated"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/entrypoint":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "updated"})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/visibility":
			var req struct {
				IsPublic bool `json:"is_public"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.IsPublic {
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"msg":  "ok",
					"data": map[string]any{"public_url": "https://my-app.public.example"},
				})
			} else {
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"msg":  "ok",
					"data": map[string]any{"app_url": "https://my-app.internal.example"},
				})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/instance/my-app/env-info":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg":  "ok",
				"data": map[string]any{"region": "us-west", "python": "3.12"},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/instance/my-app":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "deleted"})
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	})

	setupCLIEnv(t, server.URL, "session-token")

	// list
	listOut := mustRunCLI(t, "apps", "list")
	assertContains(t, listOut, "my-app")
	assertContains(t, listOut, "running")
	assertContains(t, listOut, "10.0.0.2")

	// create with secrets
	createOut := mustRunCLI(t,
		"apps", "create",
		"--name", "my-app",
		"--port", "8080",
		"--env", "API_KEY=abc123",
		"--env", "MODE=prod",
	)
	assertContains(t, createOut, "app 'my-app' created")
	assertContains(t, createOut, "Environment: 2 variables")

	// start/stop/restart
	assertContains(t, mustRunCLI(t, "apps", "start", "my-app"), "app 'my-app' started")
	assertContains(t, mustRunCLI(t, "apps", "stop", "my-app"), "app 'my-app' stopped")
	assertContains(t, mustRunCLI(t, "apps", "restart", "my-app"), "app 'my-app' restarted")

	// update --port
	assertContains(t, mustRunCLI(t, "apps", "update", "my-app", "--port", "9090"), "upstream port set to 9090")

	// update --env
	assertContains(t, mustRunCLI(t, "apps", "update", "my-app", "--env", "HELLO=world"), "secrets updated (1 vars)")

	// update --entrypoint
	assertContains(t, mustRunCLI(t, "apps", "update", "my-app", "--entrypoint", "python app.py"), "entrypoint set to python app.py")

	// update --public / --private
	assertContains(t, mustRunCLI(t, "apps", "update", "my-app", "--public"), "app 'my-app' is now public: https://my-app.public.example")
	assertContains(t, mustRunCLI(t, "apps", "update", "my-app", "--private"), "app 'my-app' is now private: https://my-app.internal.example")

	// info
	infoOut := mustRunCLI(t, "apps", "info", "my-app")
	assertContains(t, infoOut, "region: us-west")
	assertContains(t, infoOut, "python: 3.12")

	// delete
	assertContains(t, mustRunCLI(t, "apps", "delete", "my-app", "--force"), "app 'my-app' deleted")

	// Verify auth headers
	all := recorder.all()
	for i, req := range all {
		if got := req.Header.Get("Authorization"); got != "Bearer session-token" {
			t.Fatalf("request %d missing auth header: %q", i, got)
		}
	}

	// Verify create payload
	createReqs := recorder.find(http.MethodPost, "/instance")
	if len(createReqs) != 1 {
		t.Fatalf("expected one create request, got %d", len(createReqs))
	}
	createBody := decodeJSONBody(t, createReqs[0].Body)
	if createBody["name"] != "my-app" || createBody["port"] != "8080" {
		t.Fatalf("unexpected create payload: %#v", createBody)
	}
	createSecrets, ok := createBody["secrets"].(map[string]any)
	if !ok {
		t.Fatalf("expected secrets map in create payload, got %#v", createBody["secrets"])
	}
	if createSecrets["API_KEY"] != "abc123" || createSecrets["MODE"] != "prod" {
		t.Fatalf("unexpected create secrets: %#v", createSecrets)
	}

	// Verify port update payload
	portReqs := recorder.find(http.MethodPut, "/instance/my-app/upstream-port")
	if len(portReqs) != 1 {
		t.Fatalf("expected one port update request, got %d", len(portReqs))
	}
	if got := decodeJSONBody(t, portReqs[0].Body)["port"]; got != "9090" {
		t.Fatalf("expected port 9090, got %#v", got)
	}

	// Verify secrets payload
	secretReqs := recorder.find(http.MethodPut, "/instance/my-app/secrets")
	if len(secretReqs) != 1 {
		t.Fatalf("expected one secrets request, got %d", len(secretReqs))
	}
	secretBody := decodeJSONBody(t, secretReqs[0].Body)
	secrets, ok := secretBody["secrets"].(map[string]any)
	if !ok || secrets["HELLO"] != "world" {
		t.Fatalf("unexpected secrets payload: %#v", secretBody)
	}

	// Verify entrypoint payload
	entryReqs := recorder.find(http.MethodPut, "/instance/my-app/entrypoint")
	if len(entryReqs) != 1 {
		t.Fatalf("expected one entrypoint request, got %d", len(entryReqs))
	}
	if got := decodeJSONBody(t, entryReqs[0].Body)["entrypoint"]; got != "python app.py" {
		t.Fatalf("unexpected entrypoint payload: %#v", got)
	}

	// Verify visibility payloads
	visibilityReqs := recorder.find(http.MethodPut, "/instance/my-app/visibility")
	if len(visibilityReqs) != 2 {
		t.Fatalf("expected two visibility requests, got %d", len(visibilityReqs))
	}
	firstVis := decodeJSONBody(t, visibilityReqs[0].Body)
	secondVis := decodeJSONBody(t, visibilityReqs[1].Body)
	if firstVis["is_public"] != true || secondVis["is_public"] != false {
		t.Fatalf("unexpected visibility payloads: first=%#v second=%#v", firstVis, secondVis)
	}
}

func TestCLIIntegration_FilesCommandFamily(t *testing.T) {
	downloadPayload := []byte("zip-payload-for-download")
	var uploadedPath string
	var uploadedFormat string

	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/instance/my-app/files":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg": "ok",
				"data": []map[string]any{{
					"path":    "/workspace/main.py",
					"name":    "main.py",
					"content": "print('hello from test')",
				}},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/instance/my-app/files":
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "updated"})
		case r.Method == http.MethodGet && r.URL.Path == "/instance/my-app/zip":
			w.Header().Set("Content-Disposition", `attachment; filename="project.zip"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(downloadPayload)
		case r.Method == http.MethodPost && r.URL.Path == "/instance/my-app/upload":
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				http.Error(w, "invalid multipart", http.StatusBadRequest)
				return
			}
			uploadedPath = r.FormValue("path")
			uploadedFormat = r.FormValue("format")
			writeJSONResponse(w, http.StatusOK, map[string]any{"msg": "uploaded"})
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	})

	setupCLIEnv(t, server.URL, "files-token")

	workDir := t.TempDir()
	localContent := filepath.Join(workDir, "update.txt")
	if err := os.WriteFile(localContent, []byte("print('from-local-file')\n"), 0o644); err != nil {
		t.Fatalf("write local content: %v", err)
	}

	uploadDir := filepath.Join(workDir, "upload")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		t.Fatalf("mkdir upload dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "app.py"), []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatalf("write app.py: %v", err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "secret.txt"), []byte("do-not-upload"), 0o644); err != nil {
		t.Fatalf("write secret.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, ".gitignore"), []byte("secret.txt\n"), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}

	// list files
	listOut := mustRunCLI(t, "files", "list", "my-app")
	assertContains(t, listOut, "Files in app 'my-app':")
	assertContains(t, listOut, "/workspace/main.py")

	// update file
	updateOut := mustRunCLI(t, "files", "update", "my-app", "/workspace/main.py", "--file", localContent, "--append")
	assertContains(t, updateOut, "Updated /workspace/main.py in app 'my-app'")

	// download
	downloadTarget := filepath.Join(workDir, "download.zip")
	downloadOut := mustRunCLI(t, "files", "download", "my-app", "--output", downloadTarget)
	assertContains(t, downloadOut, "Downloaded")
	assertContains(t, downloadOut, downloadTarget)
	gotDownload, err := os.ReadFile(downloadTarget)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(gotDownload, downloadPayload) {
		t.Fatalf("downloaded content mismatch: got=%q want=%q", string(gotDownload), string(downloadPayload))
	}

	// push directory (always tar.gz)
	uploadOut := mustRunCLI(t, "push", "my-app", uploadDir, "--path", "/workspace")
	assertContains(t, uploadOut, "Archive uploaded and extracted successfully")

	// Verify auth headers
	all := recorder.all()
	if len(all) != 4 {
		t.Fatalf("expected 4 API requests, got %d", len(all))
	}
	for i, req := range all {
		if got := req.Header.Get("Authorization"); got != "Bearer files-token" {
			t.Fatalf("request %d missing auth header: %q", i, got)
		}
	}

	// Verify update payload
	updateReqs := recorder.find(http.MethodPut, "/instance/my-app/files")
	if len(updateReqs) != 1 {
		t.Fatalf("expected one update request, got %d", len(updateReqs))
	}
	updatePayload := decodeJSONBody(t, updateReqs[0].Body)
	if updatePayload["path"] != "/workspace/main.py" || updatePayload["write_mode"] != "append" {
		t.Fatalf("unexpected update payload: %#v", updatePayload)
	}
	if updatePayload["content"] != "print('from-local-file')\n" {
		t.Fatalf("unexpected update content: %#v", updatePayload["content"])
	}

	// Verify push was tar.gz
	if uploadedPath != "/workspace" {
		t.Fatalf("expected upload path /workspace, got %q", uploadedPath)
	}
	if uploadedFormat != "tar.gz" {
		t.Fatalf("expected upload format tar.gz, got %q", uploadedFormat)
	}
}

func TestCLIIntegration_ExecCommandStreamsSSE(t *testing.T) {
	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/instance/my-app/exec/sse" {
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("input"); got != "echo hello" {
			http.Error(w, "unexpected input query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: open\ndata: connected\n\n")
		_, _ = fmt.Fprint(w, "event: message\ndata: hello from instance\n\n")
		_, _ = fmt.Fprint(w, "event: done\ndata: complete\n\n")
	})

	setupCLIEnv(t, server.URL, "exec-token")

	stdout, _, err := runCLI(t, "exec", "my-app", "echo hello")
	if err != nil {
		t.Fatalf("exec failed: %v\nstdout:\n%s", err, stdout)
	}
	assertContains(t, stdout, "hello from instance")

	reqs := recorder.find(http.MethodGet, "/instance/my-app/exec/sse")
	if len(reqs) != 1 {
		t.Fatalf("expected one SSE request, got %d", len(reqs))
	}
	if got := reqs[0].Header.Get("Accept"); got != "text/event-stream" {
		t.Fatalf("expected Accept header text/event-stream, got %q", got)
	}
	if got := reqs[0].Header.Get("Authorization"); got != "Bearer exec-token" {
		t.Fatalf("expected auth header, got %q", got)
	}
}

func TestCLIIntegration_RunCommandInlineAndFile(t *testing.T) {
	var runBodies []map[string]any

	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/instance/run" {
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
			return
		}
		payload := map[string]any{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		runBodies = append(runBodies, payload)

		out := "inline-output"
		if len(runBodies) == 2 {
			out = "file-output"
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"msg": "ok",
			"data": map[string]any{
				"output":  out,
				"error":   "",
				"sandbox": "my-app",
			},
		})
	})

	setupCLIEnv(t, server.URL, "run-token")

	inlineOut := mustRunCLI(t, "run", "--app", "my-app", "print('inline')")
	assertContains(t, inlineOut, "inline-output")

	scriptPath := filepath.Join(t.TempDir(), "script.py")
	if err := os.WriteFile(scriptPath, []byte("print('from file')\n"), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	fileOut := mustRunCLI(t, "run", "--app", "my-app", scriptPath)
	assertContains(t, fileOut, "Running "+scriptPath+" as Python in app 'my-app'...")
	assertContains(t, fileOut, "file-output")

	if len(runBodies) != 2 {
		t.Fatalf("expected 2 run requests, got %d", len(runBodies))
	}
	if runBodies[0]["id"] != "my-app" || runBodies[0]["code"] != "print('inline')" {
		t.Fatalf("unexpected inline run payload: %#v", runBodies[0])
	}
	if runBodies[1]["id"] != "my-app" || runBodies[1]["code"] != "print('from file')\n" {
		t.Fatalf("unexpected file run payload: %#v", runBodies[1])
	}

	for i, req := range recorder.all() {
		if got := req.Header.Get("Authorization"); got != "Bearer run-token" {
			t.Fatalf("request %d missing auth header: %q", i, got)
		}
	}
}

func TestCLIIntegration_DeployJobsCommandFamily(t *testing.T) {
	server, recorder := startMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/instance/deploy":
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"msg":  "accepted",
				"data": map[string]any{"workflow_id": "wf-123", "run_id": "run-1"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/instance/my-app/deploy/wf-123/status":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg":  "ok",
				"data": map[string]any{"status": "running", "progress": "50%"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs":
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"msg":  "accepted",
				"data": map[string]any{"id": "job-1", "status": "queued"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/job-1":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg":  "ok",
				"data": map[string]any{"id": "job-1", "status": "running"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/jobs":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg": "ok",
				"data": map[string]any{
					"items": []map[string]any{{
						"id":            "job-1",
						"status":        "running",
						"command":       "python main.py",
						"instance_name": "my-app",
					}},
					"total": 1,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/job-1/restart":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg":  "ok",
				"data": map[string]any{"id": "job-2", "status": "queued"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/job-1/cancel":
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"msg":  "ok",
				"data": map[string]any{"id": "job-1", "status": "canceled"},
			})
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	})

	setupCLIEnv(t, server.URL, "workflow-token")

	// Deploy with --follow=false to get workflow ID output
	deployOut := mustRunCLI(t,
		"deploy", "my-app",
		"--repo", "https://github.com/acme/repo",
		"--cmd", "python app.py",
		"--source", "python:3.12",
		"--port", "8080",
		"--entrypoint", "python app.py",
		"--provider", "runpod",
		"--env", "API_KEY=xyz",
		"--follow=false",
	)
	assertContains(t, deployOut, "Deploy started. Workflow ID: wf-123")

	statusOut := mustRunCLI(t, "deploy", "status", "my-app", "wf-123")
	assertContains(t, statusOut, "status: running")
	assertContains(t, statusOut, "progress: 50%")

	assertContains(t, mustRunCLI(t, "jobs", "submit", "python main.py", "--app", "my-app", "--provider", "incus"), "Job submitted:")
	assertContains(t, mustRunCLI(t, "jobs", "get", "job-1"), "id: job-1")
	listOut := mustRunCLI(t, "jobs", "list", "--page", "2", "--limit", "5")
	assertContains(t, listOut, "Total: 1")
	assertContains(t, listOut, "- job-1 [running] app=my-app cmd=python main.py")
	assertContains(t, mustRunCLI(t, "jobs", "restart", "job-1"), "Job restarted:")
	assertContains(t, mustRunCLI(t, "jobs", "cancel", "job-1"), "Job canceled:")

	all := recorder.all()
	if len(all) != 7 {
		t.Fatalf("expected 7 API requests, got %d", len(all))
	}
	for i, req := range all {
		if got := req.Header.Get("Authorization"); got != "Bearer workflow-token" {
			t.Fatalf("request %d missing auth header: %q", i, got)
		}
	}

	deployReqs := recorder.find(http.MethodPost, "/instance/deploy")
	if len(deployReqs) != 1 {
		t.Fatalf("expected one deploy request, got %d", len(deployReqs))
	}
	deployBody := decodeJSONBody(t, deployReqs[0].Body)
	if deployBody["name"] != "my-app" || deployBody["repo_url"] != "https://github.com/acme/repo" {
		t.Fatalf("unexpected deploy payload: %#v", deployBody)
	}
	if deployBody["service_cmd"] != "python app.py" || deployBody["source"] != "python:3.12" {
		t.Fatalf("unexpected deploy payload: %#v", deployBody)
	}
	if deployBody["port"] != "8080" || deployBody["entrypoint"] != "python app.py" || deployBody["provider"] != "runpod" {
		t.Fatalf("unexpected deploy payload: %#v", deployBody)
	}
	deploySecrets, ok := deployBody["secrets"].(map[string]any)
	if !ok || deploySecrets["API_KEY"] != "xyz" {
		t.Fatalf("unexpected deploy secrets: %#v", deployBody["secrets"])
	}

	jobsReqs := recorder.find(http.MethodPost, "/jobs")
	if len(jobsReqs) != 1 {
		t.Fatalf("expected one jobs submit request, got %d", len(jobsReqs))
	}
	jobsBody := decodeJSONBody(t, jobsReqs[0].Body)
	if jobsBody["command"] != "python main.py" || jobsBody["instance_id"] != "my-app" || jobsBody["provider"] != "incus" {
		t.Fatalf("unexpected jobs submit payload: %#v", jobsBody)
	}

	listReqs := recorder.find(http.MethodGet, "/jobs")
	if len(listReqs) != 1 {
		t.Fatalf("expected one jobs list request, got %d", len(listReqs))
	}
	if !strings.Contains(listReqs[0].RawQuery, "page=2") || !strings.Contains(listReqs[0].RawQuery, "limit=5") {
		t.Fatalf("unexpected jobs list query: %q", listReqs[0].RawQuery)
	}
}
