package appleapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// mockToken is a fake token provider for testing.
type mockToken struct {
	token string
	err   error
}

func (m *mockToken) GetToken(_ time.Time) (string, error) {
	return m.token, m.err
}

func (m *mockToken) SetLogger(l *slog.Logger) {
}

// generateSelfSignedCert creates a temporary self-signed certificate.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load x509 keypair: %v", err)
	}
	return cert
}

// startLocalTLSServer starts a TLS + HTTP/2 server for testing.
func startLocalTLSServer(t *testing.T, handler http.Handler) (addr string, cert tls.Certificate, closeFunc func()) {
	cert = generateSelfSignedCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := &http.Server{Handler: handler}
	http2.ConfigureServer(srv, &http2.Server{})

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	return ln.Addr().String(), cert, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
}

// newTLSConfigFromCert creates a TLS config that trusts the given cert.
func newTLSConfigFromCert(cert tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	certBytes, _ := x509.ParseCertificate(cert.Certificate[0])
	roots.AddCert(certBytes)
	return &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
}

func TestClient_Do_LocalTLS(t *testing.T) {
	ResetConfig()
	// Note: t.Parallel() is skipped because subtests share a single TLS server.

	tests := map[string]struct {
		token     string
		tokenErr  error
		wantCode  int
		wantBody  string
		expectErr bool
	}{
		"success":       {token: "mock-token", wantCode: 200, wantBody: "ok"},
		"token error":   {tokenErr: fmt.Errorf("token error"), expectErr: true},
		"invalid token": {token: "wrong-token", wantCode: 401, wantBody: "invalid token"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2, got %s", r.Proto)
		}
		auth := r.Header.Get("authorization")
		if auth != "bearer mock-token" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("invalid token"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	addr, cert, closeServer := startLocalTLSServer(t, handler)
	defer closeServer()

	SetConfig(&ClientConfig{
		HTTPTimeout:         60 * time.Second,
		ReadIdleTimeout:     15 * time.Second,
		KeepAlive:           15 * time.Second,
		DialTimeout:         20 * time.Second,
		MaxIdleConnsPerHost: 100,
		TLSConfig:           newTLSConfigFromCert(cert),
	})

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient("https://"+addr, &mockToken{
				token: tt.token,
				err:   tt.tokenErr,
			})
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest("GET", "https://"+addr, nil)
			if err != nil {
				t.Fatal(err)
			}

			res, err := c.Do(req)
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			if res.StatusCode != tt.wantCode {
				t.Errorf("StatusCode: got %d, want %d", res.StatusCode, tt.wantCode)
			}

			body, _ := io.ReadAll(res.Body)
			if string(body) != tt.wantBody {
				t.Errorf("Body: got %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestClient_ConfigPropagation(t *testing.T) {
	ResetConfig()
	cfg := &ClientConfig{
		HTTPTimeout:         10 * time.Second,
		ReadIdleTimeout:     5 * time.Second,
		KeepAlive:           7 * time.Second,
		DialTimeout:         3 * time.Second,
		MaxIdleConnsPerHost: 50,
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
	}
	SetConfig(cfg)

	client, err := NewClient("https://example.com", &mockToken{})
	if err != nil {
		t.Fatal(err)
	}

	if client.HTTPClient.Timeout != cfg.HTTPTimeout {
		t.Errorf("HTTPTimeout: got %v, want %v", client.HTTPClient.Timeout, cfg.HTTPTimeout)
	}

	tr := client.HTTPClient.Transport.(*http.Transport)
	if tr.MaxIdleConnsPerHost != cfg.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %v, want %v", tr.MaxIdleConnsPerHost, cfg.MaxIdleConnsPerHost)
	}
	if reflect.DeepEqual(tr.TLSClientConfig, cfg.TLSConfig) {
		t.Error("TLSClientConfig not propagated correctly")
	}

	// Verify HTTP/2 ReadIdleTimeout
	_, tr2, err := newTransport()
	if err != nil {
		t.Fatal(err)
	}
	if tr2.ReadIdleTimeout != cfg.ReadIdleTimeout {
		t.Errorf("ReadIdleTimeout: got %v, want %v", tr2.ReadIdleTimeout, cfg.ReadIdleTimeout)
	}
}

func TestClient_Options(t *testing.T) {
	ResetConfig()
	t.Parallel()

	mockLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := map[string]struct {
		optsFunc  func() []Option
		checkFunc func(*Client) error
	}{
		"LoggerOnly": {
			optsFunc: func() []Option {
				return []Option{WithLogger(mockLogger)}
			},
			checkFunc: func(c *Client) error {
				if c.logger != mockLogger {
					return fmt.Errorf("set wrong logger: got %p, want %p", c.logger, mockLogger)
				}
				if c.Development {
					return fmt.Errorf("Development should be false")
				}
				return nil
			},
		},
		"DevelopmentOnly": {
			optsFunc: func() []Option {
				return []Option{WithDevelopment()}
			},
			checkFunc: func(c *Client) error {
				if !c.Development {
					return fmt.Errorf("development mode not enabled")
				}
				if c.logger == nil {
					return fmt.Errorf("logger should be non-nil")
				}
				return nil
			},
		},
		"LoggerAndDevelopment": {
			optsFunc: func() []Option {
				return []Option{WithLogger(mockLogger), WithDevelopment()}
			},
			checkFunc: func(c *Client) error {
				if c.logger == nil {
					return fmt.Errorf("logger not set")
				}
				if !c.Development {
					return fmt.Errorf("development mode not enabled")
				}
				return nil
			},
		},
		"CustomTransport": {
			optsFunc: func() []Option {
				customTransport := &http.Transport{}
				return []Option{WithTransport(customTransport)}
			},
			checkFunc: func(c *Client) error {
				tr, ok := c.HTTPClient.Transport.(*http.Transport)
				if !ok {
					return fmt.Errorf("Transport is not *http.Transport")
				}
				if tr == nil {
					return fmt.Errorf("custom transport not applied")
				}
				return nil
			},
		},
		"ClientTrace with Logger": func() struct {
			optsFunc  func() []Option
			checkFunc func(*Client) error
		} {
			var captureLogger *slog.Logger
			localLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

			return struct {
				optsFunc  func() []Option
				checkFunc func(*Client) error
			}{
				optsFunc: func() []Option {
					return []Option{
						WithClientTrace(func(l *slog.Logger) *httptrace.ClientTrace {
							captureLogger = l
							return DefaultClientTrace(l, slog.LevelDebug)
						}),
						WithLogger(localLogger),
					}
				},
				checkFunc: func(c *Client) error {
					if captureLogger != localLogger {
						return fmt.Errorf(
							"option WithClientTrace received wrong logger: got %p, want %p",
							captureLogger, localLogger,
						)
					}
					if c.trace == nil {
						return fmt.Errorf("Client.trace is nil")
					}
					return nil
				},
			}
		}(),
	}

	for name, tt := range tests {
		tt := tt // capture range variable
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, err := NewClient("https://example.com", &mockToken{}, tt.optsFunc()...)
			if err != nil {
				t.Fatal(err)
			}

			if err = tt.checkFunc(c); err != nil {
				t.Error(err)
			}
		})
	}
}

func ResetConfig() {
	configOnce = sync.Once{}
	sharedTransport = nil
	config = nil
}
