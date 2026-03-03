package token

// Package token provides utilities for generating and signing JWTs for Apple APIs.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
)

var _ Signer = &SignerECDSA{}

// Signer defines the interface for signing strings.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// SignerECDSA implements the Signer interface using ECDSA.
type SignerECDSA struct {
	PrivateKey *ecdsa.PrivateKey // ECDSA private key
	Hash       crypto.Hash       // Hash algorithm used for signing
}

// Sign generates a raw ECDSA signature (r||s) over the provided data.
// It supports only 256-bit curves (P-256).
func (se *SignerECDSA) Sign(data []byte) ([]byte, error) {
	if se.PrivateKey == nil {
		return nil, errors.New("missing private key")
	}
	if se.PrivateKey.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 is supported")
	}

	hash := se.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}
	if !hash.Available() {
		return nil, fmt.Errorf("hash not available: %v", hash)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, se.PrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}

	curveBits := se.PrivateKey.Curve.Params().BitSize

	// Round up curveBits to the nearest byte boundary.
	keyBytes := (curveBits + 7) / 8

	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return signature, nil
}
