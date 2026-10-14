package appleapi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/takimoto3/appleapi-core/token"
)

type MockTokenProvider struct {
	token string
	err   error
}

func (m *MockTokenProvider) GetToken(_ time.Time) (string, error) {
	return m.token, m.err
}

// --- Tests ---

func TestHTTPClientInitializers(t *testing.T) {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	cfg := &HTTPConfig{
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     2 * time.Second,
		DialTimeout:         1 * time.Second,
		KeepAlive:           3 * time.Second,
		ReadIdleTimeout:     4 * time.Second,
		HTTPTimeout:         5 * time.Second,
	}

	tests := map[string]struct {
		init         HTTPClientInitializer
		maxConns     int
		maxIdleConns int
		idleConn     time.Duration
		httpTimeout  time.Duration
		tlsConfig    *tls.Config
		readIdle     time.Duration
	}{
		"Default": {
			init:         DefaultHTTPClientInitializer(),
			maxConns:     100,
			maxIdleConns: 100,
			idleConn:     defaultTransport.IdleConnTimeout,
			httpTimeout:  0,
			tlsConfig:    &tls.Config{MaxVersion: tls.VersionTLS13},
		},
		"Configure": {
			init:         ConfigureHTTPClientInitializer(cfg),
			maxConns:     cfg.MaxConnsPerHost,
			maxIdleConns: cfg.MaxIdleConnsPerHost,
			idleConn:     cfg.IdleConnTimeout,
			httpTimeout:  cfg.HTTPTimeout,
			tlsConfig:    cfg.TLSConfig.Clone(),
			readIdle:     cfg.ReadIdleTimeout,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := tt.init()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tr, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("unexpected transport type %T", client.Transport)
			}

			if tr.MaxConnsPerHost != tt.maxConns {
				t.Errorf("MaxConnsPerHost = %d, want %d",
					tr.MaxConnsPerHost, tt.maxConns)
			}
			if tr.MaxIdleConnsPerHost != tt.maxIdleConns {
				t.Errorf("MaxIdleConnsPerHost = %d, want %d",
					tr.MaxIdleConnsPerHost, tt.maxIdleConns)
			}
			if tr.IdleConnTimeout != tt.idleConn {
				t.Errorf("IdleConnTimeout = %s, want %s",
					tr.IdleConnTimeout, tt.idleConn)
			}
			if client.Timeout != tt.httpTimeout {
				t.Errorf("Timeout = %s, want %s",
					client.Timeout, tt.httpTimeout)
			}

			if tr.Protocols == nil {
				t.Fatal("Protocols is nil")
			}
			if !tr.Protocols.HTTP1() {
				t.Error("HTTP/1 is not enabled")
			}
			if !tr.Protocols.HTTP2() {
				t.Error("HTTP/2 is not enabled")
			}

			if tt.readIdle > 0 {
				if tr.HTTP2 == nil {
					t.Fatal("HTTP2 config is nil")
				}
				if tr.HTTP2.SendPingTimeout != tt.readIdle {
					t.Errorf("SendPingTimeout = %s, want %s",
						tr.HTTP2.SendPingTimeout, tt.readIdle)
				}
			} else if tr.HTTP2 != nil && tr.HTTP2.SendPingTimeout != 0 {
				t.Errorf("SendPingTimeout = %s, want 0", tr.HTTP2.SendPingTimeout)
			}

			if diff := cmp.Diff(
				tt.tlsConfig,
				tr.TLSClientConfig,
				cmpopts.IgnoreUnexported(tls.Config{}),
			); diff != "" {
				t.Errorf("TLSClientConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewClient_Options(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	customTransport := &http.Transport{}
	mockTP := &MockTokenProvider{}
	trace := &httptrace.ClientTrace{}

	tests := map[string]struct {
		opts          []Option
		wantDev       bool
		wantLogger    *slog.Logger
		wantTransport http.RoundTripper
		wantTrace     *httptrace.ClientTrace
		wantTimeout   time.Duration
	}{
		"Development only": {
			opts:    []Option{WithDevelopment()},
			wantDev: true,
		},
		"Logger only": {
			opts:       []Option{WithLogger(logger)},
			wantLogger: logger,
		},
		"Transport and Timeout": {
			opts: []Option{
				WithTransport(customTransport),
				WithClientTimeout(3 * time.Second),
			},
			wantTransport: customTransport,
			wantTimeout:   3 * time.Second,
		},
		"ClientTimeout only": {
			opts:        []Option{WithClientTimeout(7 * time.Second)},
			wantTimeout: 7 * time.Second,
		},
		"ClientTrace only": {
			opts: []Option{
				WithClientTrace(func(l *slog.Logger) *httptrace.ClientTrace {
					return &httptrace.ClientTrace{}
				}),
			},
		},
		"All options": {
			opts: []Option{
				WithDevelopment(),
				WithLogger(logger),
				WithTransport(customTransport),
				WithClientTimeout(5 * time.Second),
				WithClientTrace(func(l *slog.Logger) *httptrace.ClientTrace {
					return trace
				}),
			},
			wantDev:       true,
			wantLogger:    logger,
			wantTransport: customTransport,
			wantTimeout:   5 * time.Second,
			wantTrace:     trace,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cli, err := NewClient(DefaultHTTPClientInitializer(), "https://example.com", mockTP, tc.opts...)
			if err != nil {
				t.Fatalf("NewClient failed: %v", err)
			}

			if cli.Development != tc.wantDev {
				t.Errorf("Development = %v, want %v", cli.Development, tc.wantDev)
			}
			if tc.wantLogger != nil && cli.Logger != tc.wantLogger {
				t.Errorf("logger pointer mismatch")
			}
			if tc.wantTransport != nil && cli.HTTPClient.Transport != tc.wantTransport {
				t.Errorf("Transport pointer mismatch")
			}
			if tc.wantTimeout != 0 && cli.HTTPClient.Timeout != tc.wantTimeout {
				t.Errorf("Timeout = %v, want %v", cli.HTTPClient.Timeout, tc.wantTimeout)
			}
			if tc.wantTrace != nil && cli.Trace != tc.wantTrace {
				t.Errorf("ClientTrace pointer mismatch")
			}
		})
	}
}

func TestNewClient_OptionOrder(t *testing.T) {
	mockTP := &MockTokenProvider{}

	withFirst := func() Option {
		return Option{
			order: 0,
			f: func(c *Client) {
				if c.Development {
					t.Errorf("withFirst should run before WithDevelopment")
				}
			},
		}
	}

	withLast := func() Option {
		return Option{
			order: ClientTrace + 1,
			f: func(c *Client) {
				if !c.Development {
					t.Errorf("withLast should run after WithDevelopment")
				}
			},
		}
	}

	_, err := NewClient(DefaultHTTPClientInitializer(), "https://example.com", mockTP,
		withLast(),
		WithDevelopment(),
		withFirst(),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
}

func TestCloseIdleConnections(t *testing.T) {
	c, _ := NewClient(DefaultHTTPClientInitializer(), "https://example.com", &MockTokenProvider{token: "t"})
	c.CloseIdleConnections() // should not panic
}

func TestClient_Do(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("server: proto = %q, want HTTP/2.0", r.Proto)
		}
		if r.TLS == nil {
			t.Error("server: r.TLS is nil")
		} else if r.TLS.NegotiatedProtocol != "h2" {
			t.Errorf("server: NegotiatedProtocol = %q, want h2", r.TLS.NegotiatedProtocol)
		}
		if strings.ToLower(r.Header.Get("Authorization")) != "bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	configure := ConfigureHTTPClientInitializer(&HTTPConfig{
		TLSConfig:           srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     2 * time.Second,
		DialTimeout:         1 * time.Second,
		KeepAlive:           3 * time.Second,
		ReadIdleTimeout:     4 * time.Second,
		HTTPTimeout:         5 * time.Second,
	})

	testTLSConfig := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	withTestRootCAs := func(init HTTPClientInitializer) HTTPClientInitializer {
		return func() (*http.Client, error) {
			client, err := init()
			if err != nil {
				return nil, err
			}
			tr, ok := client.Transport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("unexpected transport type %T", client.Transport)
			}
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			}
			tr.TLSClientConfig.RootCAs = testTLSConfig.RootCAs
			return client, nil
		}
	}

	tests := map[string]struct {
		initializer HTTPClientInitializer
		provider    token.Provider
		wantCode    int
		wantErr     bool
	}{
		"Default/valid token": {
			initializer: withTestRootCAs(DefaultHTTPClientInitializer()),
			provider:    &MockTokenProvider{token: "tok"},
			wantCode:    http.StatusOK,
		},
		"Configure/valid token": {
			initializer: configure,
			provider:    &MockTokenProvider{token: "tok"},
			wantCode:    http.StatusOK,
		},
		"Default/token error": {
			initializer: withTestRootCAs(DefaultHTTPClientInitializer()),
			provider:    &MockTokenProvider{err: errors.New("fail")},
			wantErr:     true,
		},
		"Configure/token error": {
			initializer: configure,
			provider:    &MockTokenProvider{err: errors.New("fail")},
			wantErr:     true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(tt.initializer, srv.URL, tt.provider)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			resp, err := c.Do(req)
			if resp != nil {
				defer resp.Body.Close()
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.wantCode, resp.StatusCode); diff != "" {
				t.Errorf("StatusCode mismatch (-want +got):\n%s", diff)
			}

			if resp.ProtoMajor != 2 {
				t.Errorf("response proto = %q, want HTTP/2.0", resp.Proto)
			}
			if resp.TLS == nil {
				t.Error("resp.TLS is nil, want TLS connection")
			} else if resp.TLS.NegotiatedProtocol != "h2" {
				t.Errorf("NegotiatedProtocol = %q, want h2", resp.TLS.NegotiatedProtocol)
			}
		})
	}
}
