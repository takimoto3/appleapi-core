package appleapi

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/takimoto3/appleapi-core/token"
	"golang.org/x/net/http2"
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
	cfg := &HTTPConfig{
		TLSConfig:           &tls.Config{InsecureSkipVerify: true}, // Configure用
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     2 * time.Second,
		DialTimeout:         1 * time.Second,
		KeepAlive:           3 * time.Second,
		ReadIdleTimeout:     4 * time.Second,
		HTTPTimeout:         5 * time.Second,
	}

	tests := map[string]struct {
		init  HTTPClientInitializer
		wants map[string]any
	}{
		"Default": {
			init: DefaultHTTPClientInitializer(),
			wants: map[string]any{
				"MaxConnsPerHost":     100,
				"MaxIdleConnsPerHost": 100,
				"ForceAttemptHTTP2":   true,
				"Timeout":             time.Duration(0),
				"ReadIdleTimeout":     0,
				"TLSClientConfig":     &tls.Config{MaxVersion: tls.VersionTLS13},
			},
		},
		"Configure": {
			init: ConfigureHTTPClientInitializer(cfg),
			wants: map[string]any{
				"MaxConnsPerHost":     cfg.MaxConnsPerHost,
				"MaxIdleConnsPerHost": cfg.MaxIdleConnsPerHost,
				"IdleConnTimeout":     cfg.IdleConnTimeout,
				"ForceAttemptHTTP2":   true,
				"Timeout":             cfg.HTTPTimeout,
				"ReadIdleTimeout":     cfg.ReadIdleTimeout,
				"TLSClientConfig":     func() *tls.Config { c := cfg.TLSConfig.Clone(); c.NextProtos = []string{"h2", "http/1.1"}; return c }(),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := tt.init()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var tr1 *http.Transport
			var tr2 *http2.Transport

			// Transportの型判定
			switch tr := client.Transport.(type) {
			case *http.Transport:
				tr1 = tr
			case *http2.Transport:
				tr2 = tr
				// http2.Transport wraps an *http.Transport (`t1`) but doesn't expose it.
				// We use reflection for testing purposes to inspect its properties.
				v := reflect.ValueOf(tr2).Elem().FieldByName("t1")
				if !v.IsValid() || v.IsNil() {
					t.Fatal("http2.Transport.t1 not found or nil")
				}
				tr1 = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(*http.Transport)
			default:
				t.Fatalf("unexpected transport type %T", client.Transport)
			}

			for fname, want := range tt.wants {
				var got any
				switch fname {
				case "MaxConnsPerHost":
					got = tr1.MaxConnsPerHost
				case "MaxIdleConnsPerHost":
					got = tr1.MaxIdleConnsPerHost
				case "IdleConnTimeout":
					got = tr1.IdleConnTimeout
				case "ForceAttemptHTTP2":
					got = tr1.ForceAttemptHTTP2
				case "Timeout":
					got = client.Timeout
				case "ReadIdleTimeout":
					if tr2 != nil {
						got = tr2.ReadIdleTimeout
					} else {
						got = 0
					}
				case "TLSClientConfig":
					got = tr1.TLSClientConfig
				default:
					t.Fatalf("unknown field %s", fname)
				}

				if diff := cmp.Diff(got, want, cmpopts.IgnoreUnexported(tls.Config{})); diff != "" {
					t.Errorf("%s mismatch (-got +want):\n%s", fname, diff)
				}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ToLower(r.Header.Get("Authorization")) != "bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	tests := map[string]struct {
		provider token.Provider
		wantCode int
		wantErr  bool
	}{
		"valid token": {
			provider: &MockTokenProvider{token: "tok"},
			wantCode: http.StatusOK,
			wantErr:  false,
		},
		"token error": {
			provider: &MockTokenProvider{err: errors.New("fail")},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(DefaultHTTPClientInitializer(), srv.URL, tt.provider)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
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
		})
	}
}
