package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

type APIResponse struct {
	Message string `json:"msg"`
	Data    any    `json:"data"`
}

type sandbox struct {
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

type User struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	TenantID  string `json:"tenant_id"`
}

type AuthStatusResponse struct {
	Authenticated bool `json:"authenticated"`
	User          User `json:"user"`
}

func NewAPIClient(baseURL, authToken string) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		AuthToken: authToken,
	}
}

func (c *APIClient) makeRequest(method, endpoint string, body any) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
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

	return c.HTTPClient.Do(req)
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

func (c *APIClient) ListSandboxes() ([]sandbox, error) {
	resp, err := c.makeRequest("GET", "/sandbox", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list sandboxes: %s", string(body))
	}

	var apiResp struct {
		Message string `json:"msg"`
		Data    struct {
			Items []sandbox `json:"items"`
			Total int       `json:"total"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return apiResp.Data.Items, nil
}

func (c *APIClient) CreateSandbox(name, port string, secrets map[string]string) (*sandbox, error) {
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

	resp, err := c.makeRequest("POST", "/sandbox", createReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create sandbox: %s", string(body))
	}

	var apiResp struct {
		Message string  `json:"msg"`
		Data    sandbox `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return &apiResp.Data, nil
}

func (c *APIClient) DeleteSandbox(name string) error {
	resp, err := c.makeRequest("DELETE", "/sandbox/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete sandbox: %s", string(body))
	}

	return nil
}

func (c *APIClient) StartSandbox(name string) error {
	resp, err := c.makeRequest("PUT", "/sandbox/"+name+"/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to start sandbox: %s", string(body))
	}

	return nil
}

func (c *APIClient) StopSandbox(name string) error {
	resp, err := c.makeRequest("PUT", "/sandbox/"+name+"/stop", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop sandbox: %s", string(body))
	}

	return nil
}

func (c *APIClient) RunCommand(sandboxName, command string) (string, error) {
	runReq := map[string]string{
		"command": command,
	}

	if sandboxName != "" {
		runReq["id"] = sandboxName
	}

	resp, err := c.makeRequest("POST", "/sandbox/exec", runReq)
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

type ProjectFile struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *APIClient) DownloadZip(sandboxID, dir string) (io.ReadCloser, string, error) {
	endpoint := fmt.Sprintf("/sandbox/%s/zip", sandboxID)
	if dir != "" {
		endpoint += "?dir=" + dir
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

	// Extract filename from Content-Disposition header
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

func (c *APIClient) ListFiles(sandboxID, dir string, maxDepth int) ([]ProjectFile, error) {
	endpoint := fmt.Sprintf("/sandbox/%s/files", sandboxID)
	params := []string{}
	if dir != "" {
		params = append(params, "dir="+dir)
	}
	if maxDepth > 0 {
		params = append(params, fmt.Sprintf("max_depth=%d", maxDepth))
	}
	if len(params) > 0 {
		endpoint += "?" + strings.Join(params, "&")
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

func (c *APIClient) UpdateFile(sandboxID, path, content, fileType, writeMode string) error {
	updateReq := map[string]string{
		"path":    path,
		"content": content,
		"type":    fileType,
	}
	if writeMode != "" {
		updateReq["write_mode"] = writeMode
	}

	resp, err := c.makeRequest("PUT", "/sandbox/"+sandboxID+"/files", updateReq)
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

func (c *APIClient) UploadArchive(sandboxID, archivePath, targetPath, format string) error {
	if format == "" {
		format = "zip"
	}

	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %v", err)
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("archive", filepath.Base(archivePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("failed to write file to form: %v", err)
	}

	if err := writer.WriteField("path", targetPath); err != nil {
		return fmt.Errorf("failed to write path field: %v", err)
	}
	if err := writer.WriteField("format", format); err != nil {
		return fmt.Errorf("failed to write format field: %v", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize form: %v", err)
	}

	endpoint := fmt.Sprintf("/sandbox/%s/upload", sandboxID)
	req, err := http.NewRequest("POST", c.BaseURL+endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to upload archive: %s", string(b))
	}

	return nil
}

func (c *APIClient) RunPython(sandboxName, code, entrypoint string) (string, error) {
	runReq := map[string]string{
		"code": code,
	}

	if sandboxName != "" {
		runReq["id"] = sandboxName
	}

	if entrypoint != "" {
		runReq["entrypoint"] = entrypoint
	}

	resp, err := c.makeRequest("POST", "/sandbox/run", runReq)
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
