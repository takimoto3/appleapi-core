package token

// Package token provides utilities for generating and signing JWTs for Apple APIs.

import (
	"crypto"
	"crypto/ecdsa"
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

// Sign generates an ECDSA signature for the given string.
// It supports only 256-bit curves (P-256).
func (se *SignerECDSA) Sign(data []byte) ([]byte, error) {
	if se.PrivateKey == nil {
		return nil, errors.New("missing private key")
	}
	if !se.Hash.Available() {
		se.Hash = crypto.SHA256
	}

	curveBits := se.PrivateKey.Curve.Params().BitSize
	if curveBits != 256 {
		return nil, fmt.Errorf("unsupported curve: expected P-256, got %d bits", curveBits)
	}

	h := se.Hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, se.PrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}

	// Round up curveBits to the nearest byte boundary.
	keyBytes := (curveBits + 7) / 8

	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return signature, nil
}
