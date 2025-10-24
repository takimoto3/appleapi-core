package token

// Package token provides utilities for generating and caching JWTs for Apple APIs.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

var _ Provider = &TokenProvider{}

// TokenTTL is the default time-to-live for a cached token.
// After this duration, the token is considered expired and should be refreshed.
const TokenTTL = 30 * time.Minute

// Option represents a functional option for TokenProvider configuration.
type Option func(*TokenProvider)

// WithLogger sets a custom slog.Logger.
// If not set, logging is disabled (io.Discard).
func WithLogger(l *slog.Logger) Option {
	return func(tp *TokenProvider) {
		tp.logger = l
	}
}

// Provider defines the interface for obtaining JWT-based authentication tokens.
type Provider interface {
	// GetToken returns a cached token if still valid, or generates a new one.
	//
	// Parameters:
	//   now: The current time, used for token expiration checks.
	GetToken(now time.Time) (string, error)
}

// TokenProvider generates and caches JWT tokens for Apple services (or any JWT-based API)
// It handles token expiration and signing with the provided key.
type TokenProvider struct {
	mu           sync.RWMutex  // mu protects access to currentToken and expiresAt.
	logger       *slog.Logger  // logger for structured output, can be overridden.
	signer       Signer        // signer is used to sign JWT tokens.
	keyID        string        // keyID is the Apple Key ID (or service-specific key identifier).
	teamID       string        // teamID is the Apple Team ID (or issuer identifier).
	tokenTTL     time.Duration // tokenTTL is the duration before a cached token expires.
	currentToken string        // currentToken is the currently cached JWT token.
	expiresAt    time.Time     // expiresAt is the expiration time of currentToken.
}

// NewProvider creates a new TokenProvider.
// Logging is disabled by default unless WithLogger is specified.
//
// Parameters:
//
//	keyID: The Apple Key ID.
//	teamId: The Apple Team ID.
//	secret: The ECDSA private key for signing.
//	opts: Functional options to configure the TokenProvider.
func NewProvider(keyID, teamId string, secret *ecdsa.PrivateKey, opts ...Option) Provider {
	tp := &TokenProvider{
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		signer:   &SignerECDSA{PrivateKey: secret, Hash: crypto.SHA256},
		keyID:    keyID,
		teamID:   teamId,
		tokenTTL: TokenTTL,
	}

	for _, opt := range opts {
		opt(tp)
	}

	return tp
}

// GetToken returns a valid JWT token.
// It reuses the cached token if still valid, or generates a new one.
//
// Parameters:
//
//	now: The current time, used for token expiration checks.
func (p *TokenProvider) GetToken(now time.Time) (string, error) {
	p.mu.RLock()

	if p.currentToken != "" && now.Before(p.expiresAt) {
		p.mu.RUnlock()
		return p.currentToken, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Re-check cache after acquiring write lock
	if p.currentToken != "" && now.Before(p.expiresAt) {
		return p.currentToken, nil
	}

	jwtToken := JWTToken{
		Header: Header{
			Alg: "ES256",
			Kid: p.keyID,
		},
		Payload: Payload{
			Issuer:   p.teamID,
			IssuedAt: now.Unix(),
		},
	}

	newToken, err := jwtToken.SignedString(p.signer)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}
	p.currentToken = newToken
	p.expiresAt = now.Add(p.tokenTTL)

	p.logger.Info("Token generated successfully", "expires_at", p.expiresAt)

	return p.currentToken, nil
}

// LoadPKCS8File loads an ECDSA private key from a PKCS#8 PEM file.
//
// Parameters:
//
//	path: The file path to the PKCS#8 PEM file.
func LoadPKCS8File(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("file %q does not contain valid PEM data", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from file %q: %w", path, err)
	}

	privKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key from file %q is not an ECDSA key (actual type: %T)", path, key)
	}

	return privKey, nil
}
