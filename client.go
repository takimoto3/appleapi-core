package appleapi

// Package appleapi provides a client for interacting with Apple APIs, handling JWT-based authentication.
import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"sort"
	"time"

	"github.com/takimoto3/appleapi-core/token"
	"golang.org/x/net/http2"
)

// OptionOrder defines the execution order for Client options.
// Options are applied in ascending order of these constants.
type OptionOrder int

const (
	Development OptionOrder = iota + 1
	Logger
	Transport
	ClientTimeout
	ClientTrace // Depends on Logger being already set
)

// HTTPClientInitializer is a function that returns a configured *http.Client.
type HTTPClientInitializer func() (*http.Client, error)

// DefaultHTTPClientInitializer returns a default HTTP client with TLS1.3 and HTTP/2 enabled.
func DefaultHTTPClientInitializer() HTTPClientInitializer {
	return func() (*http.Client, error) {
		// Clone the default transport to customize settings safely
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MaxVersion: tls.VersionTLS13} // Use TLS 1.3 only
		tr.MaxIdleConnsPerHost = 100                                   // Max idle connections per host
		tr.MaxConnsPerHost = 100                                       // Max total connections per host
		tr.ForceAttemptHTTP2 = true                                    // Enable HTTP/2
		return &http.Client{Transport: tr}, nil
	}
}

// ConfigureHTTPClientInitializer returns an HTTP client configured based on the given HTTPConfig.
func ConfigureHTTPClientInitializer(cfg *HTTPConfig) HTTPClientInitializer {
	return func() (*http.Client, error) {
		// Clone the default transport to customize settings safely
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.TLSConfig != nil {
			tr.TLSClientConfig = cfg.TLSConfig.Clone()
		}
		tr.MaxConnsPerHost = cfg.MaxConnsPerHost
		tr.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
		tr.IdleConnTimeout = cfg.IdleConnTimeout
		tr.DialContext = (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAlive,
		}).DialContext

		tr2, err := http2.ConfigureTransports(tr)
		if err != nil {
			return nil, err
		}
		tr2.ReadIdleTimeout = cfg.ReadIdleTimeout

		return &http.Client{Transport: tr2, Timeout: cfg.HTTPTimeout}, nil
	}
}

// Client represents an HTTP client with Apple authentication support.
type Client struct {
	Host          string                 // Base URL for Apple API
	Development   bool                   // Enable development mode
	HTTPClient    *http.Client           // Underlying HTTP client
	TokenProvider token.Provider         // Responsible for providing tokens
	Logger        *slog.Logger           // Structured logger
	Trace         *httptrace.ClientTrace // HTTP request trace hooks
}

// Option defines a configurable option for Client, including its execution order.
type Option struct {
	f     func(*Client) // Actual option logic
	order OptionOrder   // Execution order key
}

// WithDevelopment enables development mode.
func WithDevelopment() Option {
	return Option{
		f: func(c *Client) {
			if c != nil {
				c.Development = true
			}
		},
		order: Development,
	}
}

// WithLogger sets a custom structured logger.
func WithLogger(logger *slog.Logger) Option {
	return Option{
		f: func(c *Client) {
			if c != nil && logger != nil {
				c.Logger = logger
			}
		},
		order: Logger,
	}
}

// WithTransport sets a custom HTTP transport.
func WithTransport(tr http.RoundTripper) Option {
	return Option{
		f: func(c *Client) {
			if c != nil && tr != nil {
				c.HTTPClient.Transport = tr
			}
		},
		order: Transport,
	}
}

// WithClientTimeout sets a custom HTTP client timeout.
func WithClientTimeout(timeout time.Duration) Option {
	return Option{
		f: func(c *Client) {
			if c != nil {
				c.HTTPClient.Timeout = timeout
			}
		},
		order: ClientTimeout,
	}
}

// WithClientTrace sets a custom HTTP trace function.
func WithClientTrace(f func(*slog.Logger) *httptrace.ClientTrace) Option {
	return Option{
		f: func(c *Client) {
			if c != nil {
				if tr := f(c.Logger); tr != nil {
					c.Trace = tr
				}
			}
		},
		order: ClientTrace,
	}
}

// NewClient creates a new Client with a custom HTTP initializer and options.
func NewClient(initializer HTTPClientInitializer, host string, tp token.Provider, opts ...Option) (*Client, error) {
	cli, err := initializer()
	if err != nil {
		return nil, err
	}
	c := &Client{
		Host:          host,
		HTTPClient:    cli,
		TokenProvider: tp,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Sort options by their order and apply them
	sort.Slice(opts, func(i, j int) bool {
		return opts[i].order < opts[j].order
	})
	for _, opt := range opts {
		opt.f(c)
	}

	return c, nil
}

// CloseIdleConnections closes idle connections in the HTTP client.
func (c *Client) CloseIdleConnections() {
	c.HTTPClient.CloseIdleConnections()
}

// Do sends an HTTP request with a Bearer token and optional HTTP trace.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.Trace != nil {
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), c.Trace))
	}
	bearer, err := c.TokenProvider.GetToken(time.Now())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	return c.HTTPClient.Do(req)
}
