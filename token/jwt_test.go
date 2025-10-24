package token_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/takimoto3/appleapi-core/token"
)

// mockSigner implements Signer interface for testing
type mockSigner struct {
	signData []byte
	err      error
}

func (m *mockSigner) Sign(s string) ([]byte, error) {
	return m.signData, m.err
}

func TestJWTToken_SignedString(t *testing.T) {
	// Prepare JWTToken
	jwt := &token.JWTToken{
		Header: token.Header{
			Alg: "HS256",
			Kid: "testkey",
		},
		Payload: token.Payload{
			Issuer:   "issuer",
			IssuedAt: 1234567890,
		},
	}

	// Use mock signer
	signBytes := []byte("signature")
	signer := &mockSigner{signData: signBytes}

	// Generate JWT string
	tokenStr, err := jwt.SignedString(signer)
	if err != nil {
		t.Fatalf("SignedString returned error: %v", err)
	}

	// JWT should have 3 parts separated by '.'
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	// Decode and verify header
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var hdr token.Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}
	expectedHeader := token.Header{Alg: "HS256", Kid: "testkey"}
	if diff := cmp.Diff(expectedHeader, hdr); diff != "" {
		t.Errorf("header mismatch (-want +got):\n%s", diff)
	}

	// Decode and verify payload
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var pl token.Payload
	if err := json.Unmarshal(pb, &pl); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	expectedPayload := token.Payload{Issuer: "issuer", IssuedAt: 1234567890}
	if diff := cmp.Diff(expectedPayload, pl); diff != "" {
		t.Errorf("payload mismatch (-want +got):\n%s", diff)
	}

	// Verify signature
	sb, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}
	if diff := cmp.Diff(signBytes, sb); diff != "" {
		t.Errorf("signature mismatch (-want +got):\n%s", diff)
	}
}

func TestJWTToken_SignedString_SignerError(t *testing.T) {
	// Prepare JWTToken
	jwt := &token.JWTToken{
		Header: token.Header{Alg: "HS256"},
	}

	// Signer returns an error
	signer := &mockSigner{
		err: errors.New("sign failed"),
	}

	_, err := jwt.SignedString(signer)
	if err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Errorf("expected signer error, got %v", err)
	}
}
