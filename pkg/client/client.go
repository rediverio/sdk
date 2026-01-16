// Package client provides the Rediver API client.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rediverio/rediver-sdk/pkg/core"
	"github.com/rediverio/rediver-sdk/pkg/ris"
)

// Client is the Rediver API client.
// It implements the core.Pusher interface.
type Client struct {
	baseURL    string
	apiKey     string
	workerID   string // Worker ID for tracking which scanner/runner is pushing
	httpClient *http.Client
	maxRetries int
	retryDelay time.Duration
	verbose    bool
}

// Ensure Client implements core.Pusher
var _ core.Pusher = (*Client)(nil)

// Config holds client configuration.
type Config struct {
	BaseURL    string        `yaml:"base_url" json:"base_url"`
	APIKey     string        `yaml:"api_key" json:"api_key"`
	WorkerID   string        `yaml:"worker_id" json:"worker_id"` // Registered worker ID for audit trail
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
	MaxRetries int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
	Verbose    bool          `yaml:"verbose" json:"verbose"`
}

// DefaultConfig returns default client config.
func DefaultConfig() *Config {
	return &Config{
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
	}
}

// New creates a new Rediver API client.
func New(cfg *Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 2 * time.Second
	}
	return &Client{
		baseURL:    cfg.BaseURL,
		apiKey:     cfg.APIKey,
		workerID:   cfg.WorkerID,
		maxRetries: cfg.MaxRetries,
		retryDelay: cfg.RetryDelay,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		verbose: cfg.Verbose,
	}
}

// IngestResponse is the response from ingest endpoints.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	Errors          []string `json:"errors,omitempty"`
}

// IngestInput represents the backend API ingest format.
type IngestInput struct {
	Version  string          `json:"version"`
	Metadata IngestMetadata  `json:"metadata"`
	Targets  []IngestTarget  `json:"targets,omitempty"`
	Findings []IngestFinding `json:"findings,omitempty"`
	Summary  *IngestSummary  `json:"summary,omitempty"`
}

// IngestMetadata contains metadata about the scan.
type IngestMetadata struct {
	ToolName    string    `json:"tool_name"`
	ToolVersion string    `json:"tool_version"`
	ScanID      string    `json:"scan_id"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	WorkerID    string    `json:"worker_id,omitempty"`
}

// IngestTarget represents a target asset.
type IngestTarget struct {
	Type        string         `json:"type"`
	Identifier  string         `json:"identifier"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// IngestFinding represents a finding in the ingest format.
type IngestFinding struct {
	RuleID      string         `json:"rule_id"`
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	Description string         `json:"description,omitempty"`
	FilePath    string         `json:"file_path,omitempty"`
	StartLine   int            `json:"start_line,omitempty"`
	EndLine     int            `json:"end_line,omitempty"`
	StartColumn int            `json:"start_column,omitempty"`
	EndColumn   int            `json:"end_column,omitempty"`
	Snippet     string         `json:"snippet,omitempty"`
	TargetIndex int            `json:"target_index,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// IngestSummary contains summary statistics.
type IngestSummary struct {
	TotalTargets  int            `json:"total_targets"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	Duration      string         `json:"duration"`
}

// HeartbeatRequest is the heartbeat payload.
type HeartbeatRequest struct {
	Name       string          `json:"name,omitempty"`
	Status     core.AgentState `json:"status"`
	Version    string          `json:"version,omitempty"`
	Hostname   string          `json:"hostname,omitempty"`
	Message    string          `json:"message,omitempty"`
	Scanners   []string        `json:"scanners,omitempty"`
	Collectors []string        `json:"collectors,omitempty"`
	Uptime     int64           `json:"uptime_seconds,omitempty"`
	TotalScans int64           `json:"total_scans,omitempty"`
	Errors     int64           `json:"errors,omitempty"`
}

// PushFindings sends findings to Rediver.
func (c *Client) PushFindings(ctx context.Context, report *ris.Report) (*core.PushResult, error) {
	url := fmt.Sprintf("%s/api/v1/agent/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[rediver] Pushing %d findings to %s\n", len(report.Findings), url)
	}

	// Convert RIS Report to IngestInput format
	input := c.convertToIngestInput(report)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp IngestResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[rediver] Push completed: %d findings created, %d updated\n",
			resp.FindingsCreated, resp.FindingsUpdated)
	}

	success := len(resp.Errors) == 0
	message := ""
	if !success {
		message = fmt.Sprintf("%d errors occurred", len(resp.Errors))
	}

	return &core.PushResult{
		Success:         success,
		Message:         message,
		FindingsCreated: resp.FindingsCreated,
		FindingsUpdated: resp.FindingsUpdated,
		AssetsCreated:   resp.AssetsCreated,
		AssetsUpdated:   resp.AssetsUpdated,
	}, nil
}

// PushAssets sends assets to Rediver.
func (c *Client) PushAssets(ctx context.Context, report *ris.Report) (*core.PushResult, error) {
	url := fmt.Sprintf("%s/api/v1/agent/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[rediver] Pushing %d assets to %s\n", len(report.Assets), url)
	}

	// Convert RIS Report to IngestInput format (assets only)
	input := c.convertToIngestInput(report)
	input.Findings = nil // Clear findings for assets-only push

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp IngestResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	success := len(resp.Errors) == 0

	return &core.PushResult{
		Success:       success,
		AssetsCreated: resp.AssetsCreated,
		AssetsUpdated: resp.AssetsUpdated,
	}, nil
}

// SendHeartbeat sends a heartbeat to Rediver.
func (c *Client) SendHeartbeat(ctx context.Context, status *core.AgentStatus) error {
	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", c.baseURL)

	req := HeartbeatRequest{
		Name:       status.Name,
		Status:     status.Status,
		Scanners:   status.Scanners,
		Collectors: status.Collectors,
		Uptime:     status.Uptime,
		TotalScans: status.TotalScans,
		Errors:     status.Errors,
		Message:    status.Message,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	if _, err := c.doRequest(ctx, "POST", url, body); err != nil {
		return err
	}

	if c.verbose {
		fmt.Printf("[rediver] Heartbeat sent: %s\n", status.Status)
	}

	return nil
}

// TestConnection tests the API connection.
func (c *Client) TestConnection(ctx context.Context) error {
	status := &core.AgentStatus{
		Name:    "connection-test",
		Status:  core.AgentStateRunning,
		Message: "connection test",
	}
	return c.SendHeartbeat(ctx, status)
}

// doRequest performs an HTTP request with retry logic.
func (c *Client) doRequest(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: delay * 2^(attempt-1)
			backoff := c.retryDelay * time.Duration(1<<(attempt-1))
			if c.verbose {
				fmt.Printf("[rediver] Retrying request (attempt %d/%d) after %v\n", attempt, c.maxRetries, backoff)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, err := c.doRequestOnce(ctx, method, url, body)
		if err == nil {
			return data, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx) except 429 (rate limit)
		if isClientError(err) && !isRateLimitError(err) {
			return nil, err
		}

		// Don't retry on context errors
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
}

// doRequestOnce performs a single HTTP request.
func (c *Client) doRequestOnce(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "rediver-sdk/1.0")

	// Add worker ID header for audit trail
	if c.workerID != "" {
		req.Header.Set("X-Rediver-Worker-ID", c.workerID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	return data, nil
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("http %d: %s", e.StatusCode, e.Body)
}

// isClientError checks if the error is a 4xx client error.
func isClientError(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
	}
	return false
}

// isRateLimitError checks if the error is a 429 rate limit error.
func isRateLimitError(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == 429
	}
	return false
}

// SetVerbose sets verbose mode.
func (c *Client) SetVerbose(v bool) {
	c.verbose = v
}

// convertToIngestInput converts a RIS Report to IngestInput format.
func (c *Client) convertToIngestInput(report *ris.Report) *IngestInput {
	// Generate scan ID if not provided
	scanID := report.Metadata.ID
	if scanID == "" {
		scanID = generateID()
	}

	// Get tool info
	toolName := "unknown"
	toolVersion := ""
	if report.Tool != nil {
		toolName = report.Tool.Name
		toolVersion = report.Tool.Version
	}

	input := &IngestInput{
		Version: report.Version,
		Metadata: IngestMetadata{
			ToolName:    toolName,
			ToolVersion: toolVersion,
			ScanID:      scanID,
			StartTime:   report.Metadata.Timestamp,
			EndTime:     time.Now(),
			WorkerID:    c.workerID,
		},
		Targets:  make([]IngestTarget, 0, len(report.Assets)),
		Findings: make([]IngestFinding, 0, len(report.Findings)),
	}

	// Build asset index for finding references
	assetIndex := make(map[string]int)

	// Convert assets to targets
	for i, asset := range report.Assets {
		assetIndex[asset.ID] = i

		target := IngestTarget{
			Type:        string(asset.Type),
			Identifier:  asset.Value,
			Name:        asset.Name,
			Description: asset.Description,
		}

		if len(asset.Properties) > 0 {
			target.Metadata = asset.Properties
		}

		input.Targets = append(input.Targets, target)
	}

	// Convert findings
	for _, finding := range report.Findings {
		f := IngestFinding{
			RuleID:      finding.RuleID,
			Severity:    string(finding.Severity),
			Message:     finding.Title,
			Description: finding.Description,
			Fingerprint: finding.Fingerprint,
		}

		// Set location if available
		if finding.Location != nil {
			f.FilePath = finding.Location.Path
			f.StartLine = finding.Location.StartLine
			f.EndLine = finding.Location.EndLine
			f.StartColumn = finding.Location.StartColumn
			f.EndColumn = finding.Location.EndColumn
			f.Snippet = finding.Location.Snippet
		}

		// Set target index if asset reference exists
		if finding.AssetRef != "" {
			if idx, ok := assetIndex[finding.AssetRef]; ok {
				f.TargetIndex = idx
			}
		}

		// Copy properties to metadata
		if len(finding.Properties) > 0 {
			f.Metadata = finding.Properties
		}

		input.Findings = append(input.Findings, f)
	}

	// Add summary
	if len(input.Findings) > 0 || len(input.Targets) > 0 {
		bySeverity := make(map[string]int)
		for _, f := range input.Findings {
			bySeverity[f.Severity]++
		}

		input.Summary = &IngestSummary{
			TotalTargets:  len(input.Targets),
			TotalFindings: len(input.Findings),
			BySeverity:    bySeverity,
		}

		if report.Metadata.DurationMs > 0 {
			input.Summary.Duration = fmt.Sprintf("%dms", report.Metadata.DurationMs)
		}
	}

	return input
}

// generateID generates a random ID string.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
