package token_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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
func TestSignerECDSA_Sign_ParallelVerification(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := &token.SignerECDSA{
		PrivateKey: priv,
		Hash:       crypto.SHA256,
	}

	message := []byte("parallel test message")
	hashSum := sha256.Sum256(message)

	const goroutines = 10
	const iterations = 20

	for g := 0; g < goroutines; g++ {
		g := g // Capture the loop variable for the closure.
		t.Run(fmt.Sprintf("goroutine-%d", g), func(t *testing.T) {
			t.Parallel() // Mark this subtest as safe for parallel execution.
			for i := 0; i < iterations; i++ {
				sig, err := signer.Sign(message)
				if err != nil {
					t.Errorf("Sign returned error: %v", err)
					return
				}

				r := new(big.Int).SetBytes(sig[:32])
				s := new(big.Int).SetBytes(sig[32:])
				if !ecdsa.Verify(&priv.PublicKey, hashSum[:], r, s) {
					t.Error("ECDSA signature verification failed")
					return
				}
			}
		})
	}
}
