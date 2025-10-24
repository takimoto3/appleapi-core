package appleapi

// Package appleapi provides a client for interacting with Apple APIs, handling JWT-based authentication.
import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/takimoto3/appleapi-core/token"
	"golang.org/x/net/http2"
)

var config *ClientConfig

// Default global configuration for all clients.
var defaultConfig = &ClientConfig{
	HTTPTimeout:         60 * time.Second,
	ReadIdleTimeout:     15 * time.Second,
	KeepAlive:           15 * time.Second,
	DialTimeout:         20 * time.Second,
	MaxIdleConnsPerHost: 100,
	TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, // Require TLS 1.3
	},
}

// ClientConfig defines transport and timeout settings used by all clients.
type ClientConfig struct {
	// Maximum duration for a complete HTTP request.
	HTTPTimeout time.Duration

	// Idle period before sending a ping frame on HTTP/2 connections.
	ReadIdleTimeout time.Duration

	// Interval for TCP keep-alive probes.
	KeepAlive time.Duration

	// Timeout for establishing new TCP connections.
	DialTimeout time.Duration

	// Maximum number of idle connections per host.
	MaxIdleConnsPerHost int

	// TLS settings for HTTPS connections.
	TLSConfig *tls.Config
}

var sharedTransport *http.Transport
var configOnce sync.Once

// SetConfig replaces the current global configuration.
func SetConfig(cfg *ClientConfig) error {
	var initErr error
	configOnce.Do(func() {
		config = cfg
		tr, _, err := newTransport()
		if err != nil {
			initErr = err
			return
		}
		sharedTransport = tr
	})
	return initErr
}

// newTransport creates a configured HTTP/1.1 + HTTP/2 transport.
func newTransport() (*http.Transport, *http2.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
	tr.TLSClientConfig = config.TLSConfig.Clone()

	tr2, err := http2.ConfigureTransports(tr)
	if err != nil {
		return nil, nil, err
	}
	tr2.ReadIdleTimeout = config.ReadIdleTimeout

	// Custom TLS dialer with timeouts and keepalive
	tr2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   config.DialTimeout,
			KeepAlive: config.KeepAlive,
		}
		return tls.DialWithDialer(dialer, network, addr, cfg)
	}
	return tr, tr2, nil
}

// Client represents an HTTP client with Apple authentication support.
type Client struct {
	// Host is the base URL for the Apple API (e.g., "api.appstoreconnect.apple.com").
	Host string
	// Development indicates if the client is in development mode.
	Development bool
	// HTTPClient is the underlying HTTP client used for requests.
	HTTPClient http.Client
	// TokenProvider is responsible for providing authentication tokens.
	TokenProvider token.Provider
	// logger is the structured logger used by the client.
	logger *slog.Logger
	// trace holds hooks for tracing the HTTP request lifecycle.
	trace *httptrace.ClientTrace
}

// Option defines configuration options for the Client.
// Returns true if this option should be reapplied after all other options.
type Option func(*Client) bool

// WithDevelopment enables development mode.
func WithDevelopment() Option {
	return func(c *Client) bool {
		if c != nil {
			c.Development = true
		}
		return false
	}
}

// WithLogger sets a custom structured logger for the client.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) bool {
		if c != nil {
			if logger != nil {
				c.logger = logger
			}
		}
		return false
	}
}

// WithTransport sets a custom HTTP transport for the client.
func WithTransport(tr *http.Transport) Option {
	return func(c *Client) bool {
		if c != nil {
			if tr != nil {
				c.HTTPClient.Transport = tr
			}
		}
		return false
	}
}

// NewClient creates a new Client configured for the specified Apple API host
// and token provider. Functional options may be used to customize behavior.
// Returns an error if the shared transport cannot be initialized.
func NewClient(host string, tp token.Provider, opts ...Option) (*Client, error) {
	if sharedTransport == nil {
		if err := SetConfig(defaultConfig); err != nil {
			return nil, err
		}
	}

	c := &Client{
		Host: host,
		HTTPClient: http.Client{
			Transport: sharedTransport,
			Timeout:   config.HTTPTimeout,
		},
		TokenProvider: tp,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	var last Option
	for _, opt := range opts {
		if opt(nil) {
			last = opt
		}
		opt(c)
	}
	if last != nil {
		last(c)
	}

	return c, nil
}

// CloseIdleConnections closes any idle connections in the underlying transport.
func (c *Client) CloseIdleConnections() {
	c.HTTPClient.CloseIdleConnections()
}

// Do sends an HTTP request with the client's bearer token (lowercase "bearer", per Apple documentation)
// and applies any configured httptrace.ClientTrace.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.trace != nil {
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), c.trace))
	}

	bearer, err := c.TokenProvider.GetToken(time.Now())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "bearer "+bearer)

	return c.HTTPClient.Do(req)
}
