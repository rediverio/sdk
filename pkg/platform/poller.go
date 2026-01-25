package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// JobClient defines the interface for job operations.
type JobClient interface {
	// Poll polls for new jobs using long-polling.
	Poll(ctx context.Context, req *PollRequest) (*PollResponse, error)

	// AcknowledgeJob acknowledges receipt of a job.
	AcknowledgeJob(ctx context.Context, jobID string) error

	// ReportJobResult reports the result of a completed job.
	ReportJobResult(ctx context.Context, result *JobResult) error

	// ReportJobProgress reports progress on a running job.
	ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error
}

// PollRequest contains the data for polling jobs.
type PollRequest struct {
	MaxJobs       int      `json:"max_jobs"`
	Capabilities  []string `json:"capabilities,omitempty"`
	TimeoutSeconds int     `json:"timeout_seconds,omitempty"`
}

// PollResponse contains the response from job polling.
type PollResponse struct {
	Jobs              []*JobInfo `json:"jobs"`
	PollIntervalHint  int        `json:"poll_interval_hint,omitempty"` // Suggested wait before next poll
	QueueDepth        int        `json:"queue_depth,omitempty"`        // Total pending jobs
}

// JobExecutor executes platform jobs.
type JobExecutor interface {
	Execute(ctx context.Context, job *JobInfo) (*JobResult, error)
}

// PollerConfig configures the JobPoller.
type PollerConfig struct {
	// MaxConcurrentJobs is the maximum number of concurrent jobs.
	MaxConcurrentJobs int

	// PollTimeout is the long-poll timeout (how long to wait for jobs).
	PollTimeout time.Duration

	// RetryDelay is the delay between poll attempts on error.
	RetryDelay time.Duration

	// Capabilities to advertise when polling.
	Capabilities []string

	// OnJobStarted is called when a job starts executing.
	OnJobStarted func(job *JobInfo)

	// OnJobCompleted is called when a job completes (success or failure).
	OnJobCompleted func(job *JobInfo, result *JobResult)

	// Verbose enables debug logging.
	Verbose bool
}

// JobPoller polls for and executes platform jobs.
//
// The JobPoller uses long-polling to efficiently wait for jobs. When no jobs
// are available, the server holds the connection open until a job arrives or
// the timeout expires. This provides near-real-time job dispatch with minimal
// network overhead.
type JobPoller struct {
	client       JobClient
	executor     JobExecutor
	config       *PollerConfig
	leaseManager *LeaseManager

	running     int32 // atomic
	stopCh      chan struct{}
	activeJobs  sync.WaitGroup
	currentJobs int32 // atomic count
	mu          sync.Mutex
}

// NewJobPoller creates a new JobPoller.
func NewJobPoller(client JobClient, executor JobExecutor, config *PollerConfig) *JobPoller {
	if config == nil {
		config = &PollerConfig{}
	}
	if config.MaxConcurrentJobs == 0 {
		config.MaxConcurrentJobs = DefaultMaxConcurrentJobs
	}
	if config.PollTimeout == 0 {
		config.PollTimeout = DefaultPollTimeout
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}

	return &JobPoller{
		client:   client,
		executor: executor,
		config:   config,
		stopCh:   make(chan struct{}),
	}
}

// SetLeaseManager sets the lease manager for job count reporting.
func (p *JobPoller) SetLeaseManager(lm *LeaseManager) {
	p.leaseManager = lm
}

// Start starts the job poller.
func (p *JobPoller) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&p.running, 0, 1) {
		return fmt.Errorf("poller already running")
	}

	p.mu.Lock()
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	if p.config.Verbose {
		fmt.Printf("[poller] Starting (max_jobs=%d, timeout=%v)\n",
			p.config.MaxConcurrentJobs, p.config.PollTimeout)
	}

	go p.pollLoop(ctx)

	return nil
}

// Stop stops the job poller and waits for active jobs to complete.
func (p *JobPoller) Stop(timeout time.Duration) error {
	if !atomic.CompareAndSwapInt32(&p.running, 1, 0) {
		return nil // Already stopped
	}

	p.mu.Lock()
	close(p.stopCh)
	p.mu.Unlock()

	if p.config.Verbose {
		fmt.Printf("[poller] Stopping, waiting for active jobs...\n")
	}

	// Wait for active jobs with timeout
	done := make(chan struct{})
	go func() {
		p.activeJobs.Wait()
		close(done)
	}()

	select {
	case <-done:
		if p.config.Verbose {
			fmt.Printf("[poller] All jobs completed\n")
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for jobs to complete")
	}
}

// CurrentJobCount returns the current number of running jobs.
func (p *JobPoller) CurrentJobCount() int {
	return int(atomic.LoadInt32(&p.currentJobs))
}

// pollLoop is the main polling loop.
func (p *JobPoller) pollLoop(ctx context.Context) {
	for atomic.LoadInt32(&p.running) == 1 {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
			p.pollOnce(ctx)
		}
	}
}

func (p *JobPoller) pollOnce(ctx context.Context) {
	// Calculate available capacity
	current := int(atomic.LoadInt32(&p.currentJobs))
	available := p.config.MaxConcurrentJobs - current
	if available <= 0 {
		// At capacity, wait a bit before checking again
		time.Sleep(time.Second)
		return
	}

	// Create poll context with timeout
	pollCtx, cancel := context.WithTimeout(ctx, p.config.PollTimeout+5*time.Second)
	defer cancel()

	req := &PollRequest{
		MaxJobs:        available,
		Capabilities:   p.config.Capabilities,
		TimeoutSeconds: int(p.config.PollTimeout.Seconds()),
	}

	if p.config.Verbose {
		fmt.Printf("[poller] Polling for jobs (capacity=%d/%d)\n",
			available, p.config.MaxConcurrentJobs)
	}

	resp, err := p.client.Poll(pollCtx, req)
	if err != nil {
		if pollCtx.Err() != nil {
			// Context canceled or timeout - normal during shutdown
			return
		}
		if p.config.Verbose {
			fmt.Printf("[poller] Poll failed: %v\n", err)
		}
		time.Sleep(p.config.RetryDelay)
		return
	}

	if len(resp.Jobs) == 0 {
		// No jobs available - the long-poll already waited
		return
	}

	if p.config.Verbose {
		fmt.Printf("[poller] Received %d jobs (queue_depth=%d)\n",
			len(resp.Jobs), resp.QueueDepth)
	}

	// Process each job
	for _, job := range resp.Jobs {
		// Acknowledge receipt
		if err := p.client.AcknowledgeJob(ctx, job.ID); err != nil {
			if p.config.Verbose {
				fmt.Printf("[poller] Failed to acknowledge job %s: %v\n", job.ID, err)
			}
			continue
		}

		// Execute job asynchronously
		p.activeJobs.Add(1)
		atomic.AddInt32(&p.currentJobs, 1)
		if p.leaseManager != nil {
			p.leaseManager.IncrementJobs()
		}

		go p.executeJob(ctx, job)
	}
}

func (p *JobPoller) executeJob(ctx context.Context, job *JobInfo) {
	defer func() {
		p.activeJobs.Done()
		atomic.AddInt32(&p.currentJobs, -1)
	}()

	startTime := time.Now()

	if p.config.Verbose {
		fmt.Printf("[poller] Executing job %s (type=%s, tenant=%s)\n",
			job.ID, job.Type, job.TenantID)
	}

	if p.config.OnJobStarted != nil {
		p.config.OnJobStarted(job)
	}

	// Create context with job timeout
	var jobCtx context.Context
	var cancel context.CancelFunc
	if job.TimeoutSec > 0 {
		jobCtx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutSec)*time.Second)
	} else {
		jobCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Execute the job
	result, err := p.executor.Execute(jobCtx, job)

	// Build result if not provided
	if result == nil {
		result = &JobResult{
			JobID:       job.ID,
			CompletedAt: time.Now(),
			DurationMs:  time.Since(startTime).Milliseconds(),
		}
	} else {
		result.JobID = job.ID
		result.CompletedAt = time.Now()
		if result.DurationMs == 0 {
			result.DurationMs = time.Since(startTime).Milliseconds()
		}
	}

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		if p.config.Verbose {
			fmt.Printf("[poller] Job %s failed: %v\n", job.ID, err)
		}
	} else {
		result.Status = "completed"
		if p.config.Verbose {
			fmt.Printf("[poller] Job %s completed (findings=%d, duration=%dms)\n",
				job.ID, result.FindingsCount, result.DurationMs)
		}
	}

	// Update lease manager
	if p.leaseManager != nil {
		p.leaseManager.DecrementJobs(result.Status == "failed")
	}

	// Report result back to server
	if reportErr := p.client.ReportJobResult(ctx, result); reportErr != nil {
		if p.config.Verbose {
			fmt.Printf("[poller] Failed to report result for job %s: %v\n", job.ID, reportErr)
		}
	}

	if p.config.OnJobCompleted != nil {
		p.config.OnJobCompleted(job, result)
	}
}

// =============================================================================
// HTTP Client Implementation
// =============================================================================

// httpJobClient implements JobClient using HTTP.
type httpJobClient struct {
	baseURL    string
	apiKey     string
	agentID    string
	httpClient *http.Client
}

// NewHTTPJobClient creates a new HTTP-based job client.
func NewHTTPJobClient(baseURL, apiKey, agentID string, pollTimeout time.Duration) JobClient {
	return &httpJobClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		agentID: agentID,
		httpClient: &http.Client{
			// Timeout should be longer than poll timeout to allow for response
			Timeout: pollTimeout + 10*time.Second,
		},
	}
}

func (c *httpJobClient) Poll(ctx context.Context, req *PollRequest) (*PollResponse, error) {
	url := fmt.Sprintf("%s/api/v1/platform/poll", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c *httpJobClient) AcknowledgeJob(ctx context.Context, jobID string) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/ack", c.baseURL, jobID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

func (c *httpJobClient) ReportJobResult(ctx context.Context, result *JobResult) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/result", c.baseURL, result.JobID)

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

func (c *httpJobClient) ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/progress", c.baseURL, jobID)

	body, err := json.Marshal(map[string]interface{}{
		"progress": progress,
		"message":  message,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}
