package token

// Package token provides utilities for generating and signing JWTs for Apple APIs.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Header defines the JWT header fields.
type Header struct {
	Alg string `json:"alg"` // Algorithm used for signing
	Kid string `json:"kid"`
}

// Payload defines the JWT payload (claims).
type Payload struct {
	Issuer   string `json:"iss,omitempty"` // Token issuer
	IssuedAt int64  `json:"iat,omitempty"` // Issued at (Unix time)
}

// JWTClaims represents a JWT containing a header and a payload.
type JWTClaims struct {
	Header  any
	Payload any
}

// SignedString creates a signed JWT string using the provided signer.
//
//	s: The Signer implementation used to sign the JWT.
func (jwt *JWTClaims) SignedString(s Signer) (string, error) {
	header, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header to JSON: %w", err)
	}
	payload, err := json.Marshal(jwt.Payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT payload to JSON: %w", err)
	}
	// Create the base string: header.payload
	str := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	// Sign the base string
	sign, err := s.Sign([]byte(str))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT data: %w", err)
	}

	return str + "." + base64.RawURLEncoding.EncodeToString(sign), nil
}
