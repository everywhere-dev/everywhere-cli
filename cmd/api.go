package cmd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gorillaws "github.com/gorilla/websocket"
)

type APIClient struct {
	BaseURL     string
	HTTPClient  *http.Client
	HTTP1Client *http.Client
	AuthToken   string
}

type APIResponse struct {
	Message string `json:"msg"`
	Data    any    `json:"data"`
}

type instance struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	IPAddress   string `json:"ip_address"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	TenantID    string `json:"tenant_id"`
	UserID      int    `json:"user_id"`
	Description string `json:"description"`
}

type templateItem struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	SourceInstance string `json:"source_instance"`
	SnapshotName   string `json:"snapshot_name,omitempty"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
}

type User struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
}

type AuthStatusResponse struct {
	Authenticated bool `json:"authenticated"`
	User          User `json:"user"`
}

func NewAPIClient(baseURL, authToken string) *APIClient {
	// Default client (allows HTTP/2 if available)
	defaultClient := &http.Client{Timeout: 30 * time.Second}
	// Alternate client forcing HTTP/1.1 for flaky proxies/gateways
	h1Transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &APIClient{
		BaseURL:     baseURL,
		HTTPClient:  defaultClient,
		HTTP1Client: &http.Client{Timeout: 30 * time.Second, Transport: h1Transport},
		AuthToken:   authToken,
	}
}

func (c *APIClient) makeRequest(method, endpoint string, body any) (*http.Response, error) {
	var reqBody io.Reader
	var jsonBody []byte
	var err error
	if body != nil {
		jsonBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, c.BaseURL+endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil && shouldRetryOnHTTP2(err) && c.HTTP1Client != nil {
		// Rebuild the request for HTTP/1.1 client
		var bodyReader io.Reader
		if jsonBody != nil {
			bodyReader = bytes.NewBuffer(jsonBody)
		}
		req2, e2 := http.NewRequest(method, c.BaseURL+endpoint, bodyReader)
		if e2 != nil {
			return nil, err
		}
		req2.Header = req.Header.Clone()
		return c.HTTP1Client.Do(req2)
	}
	return resp, err
}

func shouldRetryOnHTTP2(err error) bool {
	if err == nil {
		return false
	}
	// Common flaky gateway/proxy errors
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	es := strings.ToLower(err.Error())
	if strings.Contains(es, "internal_error") || strings.Contains(es, "stream error") || strings.Contains(es, "http2") {
		return true
	}
	return false
}

func (c *APIClient) GetAuthStatus() (*AuthStatusResponse, error) {
	resp, err := c.makeRequest("GET", "/auth/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed: %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get auth status: %d - %s", resp.StatusCode, string(body))
	}

	var authStatus AuthStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&authStatus); err != nil {
		return nil, err
	}

	return &authStatus, nil
}

// ClaimTenantSlug claims an immutable slug for the current tenant.
func (c *APIClient) ClaimTenantSlug(slug string) (map[string]any, error) {
	body := map[string]string{"slug": slug}
	resp, err := c.makeRequest("PUT", "/tenant/slug", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim slug failed: %d - %s", resp.StatusCode, string(respBody))
	}
	var result map[string]any
	_ = json.Unmarshal(respBody, &result)
	return result, nil
}

// GetTenantInfo returns tenant info including slug.
func (c *APIClient) GetTenantInfo() (map[string]any, error) {
	resp, err := c.makeRequest("GET", "/tenant", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get tenant failed: %d - %s", resp.StatusCode, string(respBody))
	}
	var result map[string]any
	_ = json.Unmarshal(respBody, &result)
	return result, nil
}

func (c *APIClient) ListInstances() ([]instance, error) {
	resp, err := c.makeRequest("GET", "/instance", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list instances: %s", string(body))
	}

	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []instance `json:"items"`
			Total int        `json:"total"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return apiResp.Data.Items, nil
}

type createInstanceResult struct {
	Instance *instance
}

func (c *APIClient) CreateInstance(name, port string, secrets map[string]string) (*createInstanceResult, error) {
	createReq := map[string]any{}

	if name != "" {
		createReq["name"] = name
	}
	if port != "" {
		createReq["port"] = port
	}
	if len(secrets) > 0 {
		createReq["secrets"] = secrets
	}

	resp, err := c.makeRequest("POST", "/instance", createReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create instance: %s", string(body))
	}

	var apiResp struct {
		Message string   `json:"msg"`
		Data    instance `json:"data"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	return &createInstanceResult{Instance: &apiResp.Data}, nil
}

func (c *APIClient) DeleteInstance(name string) error {
	resp, err := c.makeRequest("DELETE", "/instance/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete instance: %s", string(body))
	}

	return nil
}

func (c *APIClient) StartInstance(name string) error {
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to start instance: %s", string(body))
	}

	return nil
}

func (c *APIClient) StopInstance(name string) error {
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/stop", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop instance: %s", string(body))
	}

	return nil
}

// RestartInstance restarts an instance
func (c *APIClient) RestartInstance(name string) error {
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/restart", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to restart instance: %s", string(body))
	}
	return nil
}

func (c *APIClient) RunCommand(instanceName, command string) (string, error) {
	runReq := map[string]string{
		"command": command,
	}

	if instanceName != "" {
		runReq["id"] = instanceName
	}

	resp, err := c.makeRequest("POST", "/instance/exec", runReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to run command: %s", string(body))
	}

	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Output  string `json:"output"`
			Error   string `json:"error"`
			Sandbox string `json:"sandbox"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", err
	}

	if apiResp.Data.Error != "" {
		return "", fmt.Errorf("command failed: %s", apiResp.Data.Error)
	}

	return apiResp.Data.Output, nil
}

func (c *APIClient) StreamCommand(instanceName, command string, out io.Writer) error {
	if instanceName == "" {
		instanceName = "auto"
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	u.Path = strings.TrimRight(u.Path, "/") + fmt.Sprintf("/instance/%s/exec/sse", instanceName)
	q := u.Query()
	q.Set("input", command)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "text/event-stream")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	client := *c.HTTPClient
	client.Timeout = 0

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stream exec: %d - %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	var eventType string
	var dataBuf strings.Builder

	flushEvent := func(ev, data string) (bool, error) {
		switch ev {
		case "open":
			// Suppress "starting" noise — just wait for output
		case "done":
			return true, nil
		default:
			if data != "" {
				fmt.Fprint(out, data)
				if !strings.HasSuffix(data, "\n") {
					fmt.Fprintln(out)
				}
			}
		}
		return false, nil
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			data := dataBuf.String()
			if eventType == "" {
				eventType = "message"
			}
			done, err := flushEvent(eventType, data)
			if err != nil {
				return err
			}
			if done {
				break
			}
			dataBuf.Reset()
			eventType = ""
			continue
		}

		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(line[len("event:"):])
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimSpace(line[len("data:"):]))
			continue
		}
	}

	return nil
}

// StreamLogs connects to the server-side logs SSE endpoint and streams output.
func (c *APIClient) StreamLogs(instanceName string, follow bool, lines int, out io.Writer) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	u.Path = strings.TrimRight(u.Path, "/") + fmt.Sprintf("/instance/%s/logs/sse", instanceName)
	q := u.Query()
	q.Set("follow", fmt.Sprintf("%v", follow))
	q.Set("lines", fmt.Sprintf("%d", lines))
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	client := *c.HTTPClient
	client.Timeout = 0

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stream logs: %d - %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	var eventType string
	var dataBuf strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			data := dataBuf.String()
			if eventType == "" {
				eventType = "message"
			}
			switch eventType {
			case "done":
				return nil
			case "error":
				if data != "" {
					return fmt.Errorf("%s", data)
				}
			case "log":
				if data != "" {
					fmt.Fprintln(out, data)
				}
			}
			dataBuf.Reset()
			eventType = ""
			continue
		}

		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(line[len("event:"):])
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimSpace(line[len("data:"):]))
			continue
		}
	}

	return nil
}

type ProjectFile struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *APIClient) DownloadZip(instanceID, dir string) (io.ReadCloser, string, error) {
	endpoint := fmt.Sprintf("/instance/%s/zip", instanceID)
	if dir != "" {
		endpoint += "?dir=" + url.QueryEscape(dir)
	}

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, "", fmt.Errorf("failed to download zip: %s", string(body))
	}

	filename := "download.zip"
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if idx := bytes.Index([]byte(cd), []byte(`filename="`)); idx != -1 {
			start := idx + 10
			if end := bytes.Index([]byte(cd[start:]), []byte(`"`)); end != -1 {
				filename = cd[start : start+end]
			}
		}
	}

	return resp.Body, filename, nil
}

func (c *APIClient) ListFiles(instanceID, dir string, maxDepth int) ([]ProjectFile, error) {
	endpoint := fmt.Sprintf("/instance/%s/files", instanceID)
	q := url.Values{}
	if dir != "" {
		q.Set("dir", dir)
	}
	if maxDepth > 0 {
		q.Set("max_depth", fmt.Sprintf("%d", maxDepth))
	}
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list files: %s", string(body))
	}

	var apiResp struct {
		Message string        `json:"msg"`
		Data    []ProjectFile `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return apiResp.Data, nil
}

func (c *APIClient) UpdateFile(instanceID, path, content, fileType, writeMode string) error {
	updateReq := map[string]string{
		"path":    path,
		"content": content,
		"type":    fileType,
	}
	if writeMode != "" {
		updateReq["write_mode"] = writeMode
	}

	resp, err := c.makeRequest("PUT", "/instance/"+instanceID+"/files", updateReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update file: %s", string(body))
	}

	return nil
}

func (c *APIClient) UploadArchive(instanceID, archivePath, targetPath, format string) error {
	if format == "" {
		format = "tar.gz"
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %v", err)
	}
	defer file.Close()

	// Write multipart body to a temp file so we get Content-Length without
	// buffering the entire archive in memory. fasthttp (used by the server)
	// does not support chunked transfer encoding.
	tmp, err := os.CreateTemp("", "everywhere-multipart-*")
	if err != nil {
		return fmt.Errorf("create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	writer := multipart.NewWriter(tmp)

	part, err := writer.CreateFormFile("archive", filepath.Base(archivePath))
	if err != nil {
		return fmt.Errorf("create form file: %v", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("copy archive data: %v", err)
	}

	if strings.TrimSpace(targetPath) != "" {
		if err := writer.WriteField("path", targetPath); err != nil {
			return fmt.Errorf("write path field: %v", err)
		}
	}
	if err := writer.WriteField("format", format); err != nil {
		return fmt.Errorf("write format field: %v", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %v", err)
	}

	// Seek back to start so the HTTP client can read + compute Content-Length.
	size, err := tmp.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek temp file: %v", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek temp file: %v", err)
	}

	endpoint := fmt.Sprintf("/instance/%s/upload", instanceID)
	req, err := http.NewRequest("POST", c.BaseURL+endpoint, tmp)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	client := *c.HTTPClient
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		if len(b) == 0 {
			return fmt.Errorf("failed to upload archive: HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		}
		return fmt.Errorf("failed to upload archive: HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *APIClient) RunPython(instanceName, code, entrypoint string) (string, error) {
	runReq := map[string]string{
		"code": code,
	}

	if instanceName != "" {
		runReq["id"] = instanceName
	}

	if entrypoint != "" {
		runReq["entrypoint"] = entrypoint
	}

	resp, err := c.makeRequest("POST", "/instance/run", runReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to run python: %s", string(body))
	}

	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Output  string `json:"output"`
			Error   string `json:"error"`
			Sandbox string `json:"sandbox"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", err
	}

	if apiResp.Data.Error != "" {
		return "", fmt.Errorf("python execution failed: %s", apiResp.Data.Error)
	}

	return apiResp.Data.Output, nil
}

// UpdateIdleTimeout sets the idle timeout for an instance
func (c *APIClient) UpdateIdleTimeout(name, idleTimeout string) error {
	req := map[string]any{"idle_timeout": idleTimeout}
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/idle-timeout", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update idle timeout: %s", string(body))
	}
	return nil
}

// UpdateUpstreamPort updates the upstream port for an instance
func (c *APIClient) UpdateUpstreamPort(name, port string) error {
	req := map[string]any{"port": port}
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/upstream-port", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update port: %s", string(body))
	}
	return nil
}

// UpdateSecrets updates environment variables for an instance
func (c *APIClient) UpdateSecrets(name string, secrets map[string]string) error {
	req := map[string]any{"secrets": secrets}
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/secrets", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update secrets: %s", string(body))
	}
	return nil
}

// UpdateEntrypoint updates the entrypoint for an instance
func (c *APIClient) UpdateEntrypoint(name, entrypoint string) error {
	req := map[string]any{"entrypoint": entrypoint}
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/entrypoint", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update entrypoint: %s", string(body))
	}
	return nil
}

// GetEnvInfo gets environment info for an instance
func (c *APIClient) GetEnvInfo(name string) (map[string]any, error) {
	resp, err := c.makeRequest("GET", "/instance/"+name+"/env-info", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get env info: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

// Deploy triggers deployment on an instance
func (c *APIClient) Deploy(name string, data map[string]any) (string, error) {
	if data == nil {
		data = make(map[string]any)
	}
	if _, ok := data["name"]; !ok {
		data["name"] = name
	}
	resp, err := c.makeRequest("POST", "/instance/deploy", data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to deploy: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			WorkflowID string `json:"workflow_id"`
			RunID      string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", err
	}
	return apiResp.Data.WorkflowID, nil
}

// DeployStatus fetches status for a deployment workflow
func (c *APIClient) DeployStatus(name, workflowID string) (map[string]any, error) {
	resp, err := c.makeRequest("GET", "/instance/"+name+"/deploy/"+workflowID+"/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get deploy status: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

// Rollback restores an instance to its most recent pre-deploy snapshot.
func (c *APIClient) Rollback(name string) (map[string]any, error) {
	resp, err := c.makeRequest("POST", "/instance/"+name+"/rollback", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rollback failed: %s", string(body))
	}
	var apiResp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

// CreateDeploySnapshot takes a pre-deploy snapshot of an instance.
func (c *APIClient) CreateDeploySnapshot(name string) error {
	resp, err := c.makeRequest("POST", "/instance/"+name+"/snapshot", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("snapshot failed: %s", string(body))
	}
	return nil
}

// DeployHistory lists pre-deploy snapshots for an instance.
func (c *APIClient) DeployHistory(name string) ([]map[string]any, error) {
	resp, err := c.makeRequest("GET", "/instance/"+name+"/deploys", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list deploys: %s", string(body))
	}
	var apiResp struct {
		Data struct {
			Deploys []map[string]any `json:"deploys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data.Deploys, nil
}

// DeployEventStream represents a single SSE event from the deploy workflow.
type DeployEventStream struct {
	Type      string `json:"type"`
	Message   string `json:"message"`
	Tool      string `json:"tool,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Iteration int    `json:"iteration,omitempty"`
	Timestamp int64  `json:"ts"`
}

// StreamDeployEvents connects to the deploy SSE endpoint and sends events to the channel.
// It blocks until the stream ends (done/error event) or the caller closes done.
func (c *APIClient) StreamDeployEvents(name, workflowID string, events chan<- DeployEventStream) error {
	defer close(events)

	sseURL := c.BaseURL + "/instance/" + name + "/deploy/" + workflowID + "/events"
	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	// Use a client with no timeout for SSE streaming
	sseClient := &http.Client{Timeout: 0}
	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SSE endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments (heartbeats) and empty lines
		if strings.HasPrefix(line, ":") || line == "" {
			continue
		}

		// Skip event type lines
		if strings.HasPrefix(line, "event:") {
			continue
		}

		// Parse data lines
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			var ev DeployEventStream
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				continue // skip malformed events
			}
			events <- ev
			if ev.Type == "done" || ev.Type == "error" {
				return nil
			}
		}
	}
	return scanner.Err()
}

// Job-related methods
func (c *APIClient) SubmitJob(data map[string]any) (map[string]any, error) {
	resp, err := c.makeRequest("POST", "/jobs", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to submit job: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

func (c *APIClient) GetJob(id string) (map[string]any, error) {
	resp, err := c.makeRequest("GET", "/jobs/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get job: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

func (c *APIClient) ListJobs(page, limit int) ([]map[string]any, int, error) {
	endpoint := fmt.Sprintf("/jobs?page=%d&limit=%d", page, limit)
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("failed to list jobs: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, 0, err
	}
	return apiResp.Data.Items, apiResp.Data.Total, nil
}

func (c *APIClient) RestartJob(id string) (map[string]any, error) {
	resp, err := c.makeRequest("POST", "/jobs/"+id+"/restart", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to restart job: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

func (c *APIClient) CancelJob(id string) (map[string]any, error) {
	resp, err := c.makeRequest("POST", "/jobs/"+id+"/cancel", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to cancel job: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}

// ── API Keys ──────────────────────────────────────────────────────────────────

type apiKeyItem struct {
	ID        uint    `json:"id"`
	Name      string  `json:"name"`
	Key       string  `json:"key,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at,omitempty"`
}

func (c *APIClient) ListAPIKeys() ([]apiKeyItem, int, error) {
	resp, err := c.makeRequest("GET", "/api-keys", nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("failed to list API keys: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []apiKeyItem `json:"items"`
			Total int          `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, 0, err
	}
	return apiResp.Data.Items, apiResp.Data.Total, nil
}

func (c *APIClient) CreateAPIKey(name string) (*apiKeyItem, error) {
	resp, err := c.makeRequest("POST", "/api-keys", map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create API key: %s", string(body))
	}
	var apiResp struct {
		Message string     `json:"msg"`
		Data    apiKeyItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

func (c *APIClient) DeleteAPIKey(id string) error {
	resp, err := c.makeRequest("DELETE", "/api-keys/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete API key: %s", string(body))
	}
	return nil
}

func (c *APIClient) RotateAPIKey(id string) (*apiKeyItem, error) {
	resp, err := c.makeRequest("PUT", "/api-keys/"+id+"/rotate", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to rotate API key: %s", string(body))
	}
	var apiResp struct {
		Message string     `json:"msg"`
		Data    apiKeyItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

// ── Port Preview URLs ─────────────────────────────────────────────────────────

func (c *APIClient) GetPortPreviewURL(name, port string) (string, error) {
	resp, err := c.makeRequest("GET", "/instance/"+name+"/ports/"+port+"/preview-url", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get preview URL: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			URL string `json:"preview_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", err
	}
	return apiResp.Data.URL, nil
}

// ── Templates ─────────────────────────────────────────────────────────────────

func (c *APIClient) CreateTemplate(name, description, sourceInstance string) (*templateItem, error) {
	req := map[string]any{
		"name":            name,
		"source_instance": sourceInstance,
	}
	if description != "" {
		req["description"] = description
	}
	resp, err := c.makeRequest("POST", "/template", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create template: %s", string(body))
	}
	var apiResp struct {
		Message string       `json:"msg"`
		Data    templateItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

func (c *APIClient) ListTemplates() ([]templateItem, error) {
	resp, err := c.makeRequest("GET", "/template", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list templates: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []templateItem `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data.Items, nil
}

func (c *APIClient) GetTemplate(id string) (*templateItem, error) {
	resp, err := c.makeRequest("GET", "/template/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get template: %s", string(body))
	}
	var apiResp struct {
		Message string       `json:"msg"`
		Data    templateItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

func (c *APIClient) DeleteTemplate(id string) error {
	resp, err := c.makeRequest("DELETE", "/template/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete template: %s", string(body))
	}
	return nil
}

// ── Buckets ───────────────────────────────────────────────────────────────────

type bucketItem struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	S3Bucket   string `json:"s3_bucket,omitempty"`
	Size       string `json:"size,omitempty"`
	Status     string `json:"status"`
	S3Endpoint string `json:"s3_endpoint,omitempty"`
	AccessKey  string `json:"access_key,omitempty"`
	SecretKey  string `json:"secret_key,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func (c *APIClient) CreateBucket(name, size string) (*bucketItem, error) {
	req := map[string]any{"name": name}
	if size != "" {
		req["size"] = size
	}
	resp, err := c.makeRequest("POST", "/bucket", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create bucket: %s", string(body))
	}
	var apiResp struct {
		Message string     `json:"msg"`
		Data    bucketItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

func (c *APIClient) ListBuckets() ([]bucketItem, error) {
	resp, err := c.makeRequest("GET", "/bucket", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list buckets: %s", string(body))
	}
	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []bucketItem `json:"items"`
			Total int          `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data.Items, nil
}

func (c *APIClient) GetBucket(id string) (*bucketItem, error) {
	resp, err := c.makeRequest("GET", "/bucket/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get bucket: %s", string(body))
	}
	var apiResp struct {
		Message string     `json:"msg"`
		Data    bucketItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return &apiResp.Data, nil
}

func (c *APIClient) DeleteBucket(id string) error {
	resp, err := c.makeRequest("DELETE", "/bucket/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete bucket: %s", string(body))
	}
	return nil
}

// ConnectTerminalWebSocket opens a WebSocket connection to the instance terminal.
func (c *APIClient) ConnectTerminalWebSocket(instanceID string) (*gorillaws.Conn, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	// Use ws. subdomain for WebSocket traffic (api. has WAF that blocks upgrades)
	if strings.HasPrefix(u.Host, "api.") {
		u.Host = "ws." + u.Host[len("api."):]
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/instance/" + instanceID + "/terminal"

	header := http.Header{}
	if c.AuthToken != "" {
		header.Set("Authorization", "Bearer "+c.AuthToken)
	}
	dialer := gorillaws.Dialer{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"http/1.1"},
		},
	}
	conn, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("websocket dial failed (%d): %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return conn, nil
}

// UpdateVisibility toggles public availability for an instance
// Returns the response data map which may include public_url/app_url
func (c *APIClient) UpdateVisibility(name string, isPublic bool) (map[string]any, error) {
	req := map[string]any{"is_public": isPublic}
	resp, err := c.makeRequest("PUT", "/instance/"+name+"/visibility", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to update visibility: %s", string(body))
	}
	var apiResp struct {
		Message string         `json:"msg"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	return apiResp.Data, nil
}
