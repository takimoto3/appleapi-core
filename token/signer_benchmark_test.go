package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func newTestSigner(b *testing.B) *SignerECDSA {
	b.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	return &SignerECDSA{
		PrivateKey: priv,
	}
}

func BenchmarkSignerECDSA_Sign(b *testing.B) {
	signer := newTestSigner(b)
	payload := []byte("header.payload") // JWT signing input

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignerECDSA_Sign_Parallel(b *testing.B) {
	signer := newTestSigner(b)
	payload := []byte("header.payload")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := signer.Sign(payload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
