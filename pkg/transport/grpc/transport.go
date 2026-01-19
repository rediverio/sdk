// Package grpc provides a gRPC transport layer for the Rediver SDK client.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// Transport provides gRPC connectivity for the SDK client.
type Transport struct {
	conn    *grpc.ClientConn
	config  *Config
	mu      sync.RWMutex
	verbose bool
}

// Config holds gRPC transport configuration.
type Config struct {
	// Server address (host:port)
	Address string `yaml:"address" json:"address"`

	// Authentication
	APIKey   string `yaml:"api_key" json:"api_key"`
	WorkerID string `yaml:"worker_id" json:"worker_id"`

	// TLS configuration
	UseTLS             bool   `yaml:"use_tls" json:"use_tls"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	CertFile           string `yaml:"cert_file" json:"cert_file"`

	// Connection settings
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	KeepAliveTime    time.Duration `yaml:"keepalive_time" json:"keepalive_time"`
	KeepAliveTimeout time.Duration `yaml:"keepalive_timeout" json:"keepalive_timeout"`
	MaxRecvMsgSize   int           `yaml:"max_recv_msg_size" json:"max_recv_msg_size"`
	MaxSendMsgSize   int           `yaml:"max_send_msg_size" json:"max_send_msg_size"`

	// Debug
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// DefaultConfig returns default gRPC config.
func DefaultConfig() *Config {
	return &Config{
		Address:          "localhost:9090",
		UseTLS:           true,
		Timeout:          30 * time.Second,
		KeepAliveTime:    30 * time.Second,
		KeepAliveTimeout: 10 * time.Second,
		MaxRecvMsgSize:   50 * 1024 * 1024, // 50MB
		MaxSendMsgSize:   50 * 1024 * 1024, // 50MB
	}
}

// NewTransport creates a new gRPC transport.
func NewTransport(cfg *Config) *Transport {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Transport{
		config:  cfg,
		verbose: cfg.Verbose,
	}
}

// Connect establishes the gRPC connection.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return nil // Already connected
	}

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(t.config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(t.config.MaxSendMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                t.config.KeepAliveTime,
			Timeout:             t.config.KeepAliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithUnaryInterceptor(t.authInterceptor()),
		grpc.WithStreamInterceptor(t.streamAuthInterceptor()),
	}

	// TLS configuration
	if t.config.UseTLS {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.config.InsecureSkipVerify, //nolint:gosec // Intentional for dev environments
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if t.verbose {
		fmt.Printf("[grpc] Connecting to %s (TLS: %v)\n", t.config.Address, t.config.UseTLS)
	}

	//nolint:staticcheck // Using DialContext for backward compatibility until fully migrated to NewClient
	conn, err := grpc.DialContext(ctx, t.config.Address, opts...)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}

	t.conn = conn

	if t.verbose {
		fmt.Printf("[grpc] Connected to %s\n", t.config.Address)
	}

	return nil
}

// Close closes the gRPC connection.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil

	if t.verbose {
		fmt.Println("[grpc] Connection closed")
	}

	return err
}

// Conn returns the underlying gRPC connection.
func (t *Transport) Conn() *grpc.ClientConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// IsConnected returns true if connected.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn != nil
}

// authInterceptor adds authentication metadata to unary calls.
func (t *Transport) authInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = t.addAuthMetadata(ctx)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// streamAuthInterceptor adds authentication metadata to streaming calls.
func (t *Transport) streamAuthInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = t.addAuthMetadata(ctx)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// addAuthMetadata adds authentication headers to context.
func (t *Transport) addAuthMetadata(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + t.config.APIKey,
	})
	if t.config.WorkerID != "" {
		md.Set("x-worker-id", t.config.WorkerID)
	}
	return metadata.NewOutgoingContext(ctx, md)
}
