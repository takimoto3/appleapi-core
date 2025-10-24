package token

// Package token provides utilities for generating and signing JWTs for Apple APIs.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
)

var _ Signer = &SignerECDSA{}

// Signer defines the interface for signing strings.
type Signer interface {
	// Sign returns the signature for the given string.
	//
	// Parameters:
	//   s: The string to be signed.
	Sign(s string) ([]byte, error)
}

// SignerECDSA implements the Signer interface using ECDSA.
type SignerECDSA struct {
	PrivateKey *ecdsa.PrivateKey // ECDSA private key
	Hash       crypto.Hash       // Hash algorithm used for signing
}

// Sign generates an ECDSA signature for the given string.
// It supports only 256-bit curves (P-256).
//
// Parameters:
//
//	str: The string to be signed.
func (se *SignerECDSA) Sign(str string) ([]byte, error) {
	hasher := se.Hash.New()
	hasher.Write([]byte(str))

	r, s, err := ecdsa.Sign(rand.Reader, se.PrivateKey, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	curveBits := se.PrivateKey.Curve.Params().BitSize
	if curveBits != 256 {
		return nil, fmt.Errorf("unsupported elliptic curve size for ECDSA key: expected 256 bits, got %d", curveBits)
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes = keyBytes + 1
	}

	sign := make([]byte, 2*keyBytes)
	r.FillBytes(sign[0:keyBytes])
	s.FillBytes(sign[keyBytes:])

	return sign, nil
}
