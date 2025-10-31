package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/takimoto3/appleapi-core/token"
)

// mockHandler captures log messages
type mockHandler struct {
	calls []string
}

func (m *mockHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (m *mockHandler) Handle(ctx context.Context, r slog.Record) error {
	m.calls = append(m.calls, r.Message)
	return nil
}

func (m *mockHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(name string) slog.Handler {
	return m
}

func TestTokenProvider_GetToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mockH := &mockHandler{}
	logger := slog.New(mockH)
	tp := token.NewProvider("ABC123DEFG", "TEAMID1234", priv, token.WithLogger(logger))

	now := time.Now()

	tests := []struct {
		name    string
		offset  time.Duration
		wantNew bool // whether we expect a new token
	}{
		{"first call generates token", 0, true},
		{"second call within TTL reuses token", 1 * time.Minute, false},
		{"third call after TTL generates new token", token.TokenTTL + 1*time.Second, true},
	}

	var lastToken string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr, err := tp.GetToken(now.Add(tt.offset))
			if err != nil {
				t.Fatalf("GetToken failed: %v", err)
			}
			if tokenStr == "" {
				t.Fatal("expected non-empty token")
			}

			if tt.wantNew {
				if lastToken != "" && cmp.Diff(tokenStr, lastToken) == "" {
					t.Fatal("expected a new token, got the same as previous")
				}
			} else {
				if cmp.Diff(tokenStr, lastToken) != "" && lastToken != "" {
					t.Fatal("expected cached token, got a different token")
				}
			}
			lastToken = tokenStr

			// Convert logs to map for existence check
			logged := make(map[string]struct{})
			for _, msg := range mockH.calls {
				logged[msg] = struct{}{}
			}
			if _, ok := logged["Token generated successfully"]; !ok {
				t.Fatal("expected log message for token generation")
			}
		})
	}
}

// generateECDSAP8Key generates an ECDSA private key and encodes it into PKCS#8 PEM format.
func generateECDSAP8Key(t *testing.T, tmpDir string) string {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	filePath := filepath.Join(tmpDir, "test_ecdsa.p8")
	if err := os.WriteFile(filePath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write temporary ECDSA P8 file: %v", err)
	}
	return filePath
}

// generateRSAP8Key generates an RSA private key and encodes it into PKCS#8 PEM format.
func generateRSAP8Key(t *testing.T, tmpDir string) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	filePath := filepath.Join(tmpDir, "test_rsa.p8")
	if err := os.WriteFile(filePath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write temporary RSA P8 file: %v", err)
	}
	return filePath
}

// generateInvalidP8File creates a file with invalid PEM content.
func generateInvalidP8File(t *testing.T, tmpDir string) string {
	filePath := filepath.Join(tmpDir, "invalid.p8")
	if err := os.WriteFile(filePath, []byte("-----BEGIN PRIVATE KEY-----\nINVALIDPEMDATA\n-----END PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatalf("failed to write temporary invalid P8 file: %v", err)
	}
	return filePath
}

func TestLoadP8File(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := map[string]struct {
		setup       func(t *testing.T, dir string) string
		wantErr     bool
		errContains string
	}{
		"ValidP8KeyFile": {
			setup:       generateECDSAP8Key,
			wantErr:     false,
			errContains: "",
		},
		"NonExistentP8KeyFile": {
			setup:       func(t *testing.T, dir string) string { return "non_existent.p8" },
			wantErr:     true,
			errContains: "failed to read file",
		},
		"InvalidP8KeyFileFormat": {
			setup:       generateInvalidP8File,
			wantErr:     true,
			errContains: "does not contain valid PEM data",
		},
		"P8ContainsRSAKeyExpectedECDSA": {
			setup:       generateRSAP8Key,
			wantErr:     true,
			errContains: "is not an ECDSA key (actual type:",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			filePath := tc.setup(t, tmpDir)

			key, err := token.LoadPKCS8File(filePath)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, but got nil")
				}
				if key != nil {
					t.Errorf("expected nil key on error, but got %v", key)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error message to contain %q, but got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("failed unexpectedly for valid file: %v", err)
				}
				if key == nil {
					t.Errorf("private key is nil")
				}
			}
		})
	}
}
