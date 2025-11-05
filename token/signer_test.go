package token_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/takimoto3/appleapi-core/token"
)

func TestSignerECDSA_Sign(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := &token.SignerECDSA{
		PrivateKey: priv,
		Hash:       crypto.SHA256,
	}

	message := []byte("test message")

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("unexpected signature length: got %d, want 64", len(sig))
	}

	hash := sha256.Sum256([]byte(message))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		t.Errorf("ECDSA signature verification failed")
	}
}

func TestSignerECDSA_UnsupportedCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := &token.SignerECDSA{
		PrivateKey: priv,
		Hash:       crypto.SHA256,
	}

	_, err = signer.Sign([]byte("message"))
	if err == nil {
		t.Fatal("expected error for unsupported curve, got nil")
	}
}
