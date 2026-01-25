package platform

import (
	"context"
	"fmt"
	"time"
)

// ClientConfig configures the PlatformClient.
type ClientConfig struct {
	// BaseURL is the API base URL.
	BaseURL string

	// APIKey is the agent's API key.
	APIKey string

	// AgentID is the agent's ID.
	AgentID string

	// PollTimeout is the long-poll timeout for job polling.
	PollTimeout time.Duration

	// Verbose enables debug logging.
	Verbose bool
}

// PlatformClient provides a unified interface for platform agent operations.
// It implements LeaseClient and JobClient interfaces.
type PlatformClient struct {
	leaseClient LeaseClient
	jobClient   JobClient
	config      *ClientConfig
}

// NewPlatformClient creates a new PlatformClient.
func NewPlatformClient(config *ClientConfig) *PlatformClient {
	if config.PollTimeout == 0 {
		config.PollTimeout = DefaultPollTimeout
	}

	return &PlatformClient{
		leaseClient: NewHTTPLeaseClient(config.BaseURL, config.APIKey, config.AgentID),
		jobClient:   NewHTTPJobClient(config.BaseURL, config.APIKey, config.AgentID, config.PollTimeout),
		config:      config,
	}
}

// =============================================================================
// LeaseClient Implementation
// =============================================================================

// RenewLease implements LeaseClient.
func (c *PlatformClient) RenewLease(ctx context.Context, req *LeaseRenewRequest) (*LeaseRenewResponse, error) {
	return c.leaseClient.RenewLease(ctx, req)
}

// ReleaseLease implements LeaseClient.
func (c *PlatformClient) ReleaseLease(ctx context.Context) error {
	return c.leaseClient.ReleaseLease(ctx)
}

// =============================================================================
// JobClient Implementation
// =============================================================================

// Poll implements JobClient.
func (c *PlatformClient) Poll(ctx context.Context, req *PollRequest) (*PollResponse, error) {
	return c.jobClient.Poll(ctx, req)
}

// AcknowledgeJob implements JobClient.
func (c *PlatformClient) AcknowledgeJob(ctx context.Context, jobID string) error {
	return c.jobClient.AcknowledgeJob(ctx, jobID)
}

// ReportJobResult implements JobClient.
func (c *PlatformClient) ReportJobResult(ctx context.Context, result *JobResult) error {
	return c.jobClient.ReportJobResult(ctx, result)
}

// ReportJobProgress implements JobClient.
func (c *PlatformClient) ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error {
	return c.jobClient.ReportJobProgress(ctx, jobID, progress, message)
}

// =============================================================================
// Interface assertions
// =============================================================================

var _ LeaseClient = (*PlatformClient)(nil)
var _ JobClient = (*PlatformClient)(nil)

// =============================================================================
// Platform Agent Builder
// =============================================================================

// AgentBuilder provides a fluent API for building a platform agent.
type AgentBuilder struct {
	config          *ClientConfig
	leaseConfig     *LeaseConfig
	pollerConfig    *PollerConfig
	executor        JobExecutor
	metricsCollector MetricsCollector
	onLeaseExpired  func()
	onJobStarted    func(*JobInfo)
	onJobCompleted  func(*JobInfo, *JobResult)
}

// NewAgentBuilder creates a new AgentBuilder.
func NewAgentBuilder() *AgentBuilder {
	return &AgentBuilder{
		config:       &ClientConfig{},
		leaseConfig:  &LeaseConfig{},
		pollerConfig: &PollerConfig{},
	}
}

// WithCredentials sets the agent credentials.
func (b *AgentBuilder) WithCredentials(baseURL, apiKey, agentID string) *AgentBuilder {
	b.config.BaseURL = baseURL
	b.config.APIKey = apiKey
	b.config.AgentID = agentID
	return b
}

// WithLeaseDuration sets the lease duration.
func (b *AgentBuilder) WithLeaseDuration(d time.Duration) *AgentBuilder {
	b.leaseConfig.LeaseDuration = d
	return b
}

// WithRenewInterval sets the lease renewal interval.
func (b *AgentBuilder) WithRenewInterval(d time.Duration) *AgentBuilder {
	b.leaseConfig.RenewInterval = d
	return b
}

// WithMaxJobs sets the maximum concurrent jobs.
func (b *AgentBuilder) WithMaxJobs(n int) *AgentBuilder {
	b.leaseConfig.MaxJobs = n
	b.pollerConfig.MaxConcurrentJobs = n
	return b
}

// WithPollTimeout sets the poll timeout.
func (b *AgentBuilder) WithPollTimeout(d time.Duration) *AgentBuilder {
	b.config.PollTimeout = d
	b.pollerConfig.PollTimeout = d
	return b
}

// WithCapabilities sets the agent capabilities.
func (b *AgentBuilder) WithCapabilities(caps ...string) *AgentBuilder {
	b.pollerConfig.Capabilities = caps
	return b
}

// WithExecutor sets the job executor.
func (b *AgentBuilder) WithExecutor(executor JobExecutor) *AgentBuilder {
	b.executor = executor
	return b
}

// WithMetricsCollector sets the metrics collector.
func (b *AgentBuilder) WithMetricsCollector(collector MetricsCollector) *AgentBuilder {
	b.metricsCollector = collector
	return b
}

// OnLeaseExpired sets the callback for lease expiration.
func (b *AgentBuilder) OnLeaseExpired(fn func()) *AgentBuilder {
	b.onLeaseExpired = fn
	return b
}

// OnJobStarted sets the callback for job start.
func (b *AgentBuilder) OnJobStarted(fn func(*JobInfo)) *AgentBuilder {
	b.onJobStarted = fn
	return b
}

// OnJobCompleted sets the callback for job completion.
func (b *AgentBuilder) OnJobCompleted(fn func(*JobInfo, *JobResult)) *AgentBuilder {
	b.onJobCompleted = fn
	return b
}

// WithVerbose enables verbose logging.
func (b *AgentBuilder) WithVerbose(v bool) *AgentBuilder {
	b.config.Verbose = v
	b.leaseConfig.Verbose = v
	b.pollerConfig.Verbose = v
	return b
}

// Build creates a PlatformAgent from the builder configuration.
func (b *AgentBuilder) Build() (*PlatformAgent, error) {
	if b.config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if b.config.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	if b.config.AgentID == "" {
		return nil, fmt.Errorf("agent ID is required")
	}
	if b.executor == nil {
		return nil, fmt.Errorf("executor is required")
	}

	// Apply callbacks
	b.leaseConfig.OnLeaseExpired = b.onLeaseExpired
	b.leaseConfig.MetricsCollector = b.metricsCollector
	b.pollerConfig.OnJobStarted = b.onJobStarted
	b.pollerConfig.OnJobCompleted = b.onJobCompleted

	client := NewPlatformClient(b.config)

	leaseManager := NewLeaseManager(client, b.leaseConfig)
	poller := NewJobPoller(client, b.executor, b.pollerConfig)
	poller.SetLeaseManager(leaseManager)

	return &PlatformAgent{
		client:       client,
		leaseManager: leaseManager,
		poller:       poller,
		config:       b.config,
	}, nil
}

// =============================================================================
// Platform Agent
// =============================================================================

// PlatformAgent represents a fully configured platform agent.
type PlatformAgent struct {
	client       *PlatformClient
	leaseManager *LeaseManager
	poller       *JobPoller
	config       *ClientConfig
}

// Start starts the platform agent (lease manager + job poller).
func (a *PlatformAgent) Start(ctx context.Context) error {
	if a.config.Verbose {
		fmt.Printf("[agent] Starting platform agent %s\n", a.config.AgentID)
	}

	// Start lease manager first
	if err := a.leaseManager.Start(ctx); err != nil {
		return fmt.Errorf("start lease manager: %w", err)
	}

	// Start job poller
	if err := a.poller.Start(ctx); err != nil {
		// Stop lease manager if poller fails
		_ = a.leaseManager.Stop(ctx)
		return fmt.Errorf("start job poller: %w", err)
	}

	if a.config.Verbose {
		fmt.Printf("[agent] Platform agent started\n")
	}

	return nil
}

// Stop stops the platform agent gracefully.
func (a *PlatformAgent) Stop(ctx context.Context, timeout time.Duration) error {
	if a.config.Verbose {
		fmt.Printf("[agent] Stopping platform agent...\n")
	}

	// Stop poller first (stop accepting new jobs)
	if err := a.poller.Stop(timeout); err != nil {
		if a.config.Verbose {
			fmt.Printf("[agent] Warning: poller stop error: %v\n", err)
		}
	}

	// Then release lease
	if err := a.leaseManager.Stop(ctx); err != nil {
		if a.config.Verbose {
			fmt.Printf("[agent] Warning: lease release error: %v\n", err)
		}
	}

	if a.config.Verbose {
		fmt.Printf("[agent] Platform agent stopped\n")
	}

	return nil
}

// Status returns the current agent status.
func (a *PlatformAgent) Status() *AgentStatus {
	leaseStatus := a.leaseManager.GetStatus()

	return &AgentStatus{
		AgentID:     a.config.AgentID,
		Running:     leaseStatus.Running,
		Healthy:     leaseStatus.Healthy,
		CurrentJobs: a.poller.CurrentJobCount(),
		LastRenew:   leaseStatus.LastRenewTime,
		LastError:   leaseStatus.LastError,
	}
}

// AgentStatus represents the current agent status.
type AgentStatus struct {
	AgentID     string
	Running     bool
	Healthy     bool
	CurrentJobs int
	LastRenew   time.Time
	LastError   error
}
