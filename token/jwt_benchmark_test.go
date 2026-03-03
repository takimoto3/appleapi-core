package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/takimoto3/appleapi-core/token"
)

// --- Mock signer for lightweight benchmark ---
type benchMockSigner struct{}

func (m *benchMockSigner) Sign(data []byte) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}

func BenchmarkJWT_SignedString_Mock(b *testing.B) {
	jwt := &token.JWTClaims{
		Header:  token.Header{Alg: "HS256", Kid: "keyid"},
		Payload: token.Payload{Issuer: "issuer", IssuedAt: 1234567890},
	}
	signer := &benchMockSigner{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwt.SignedString(signer)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWT_SignedString_Mock_Parallel(b *testing.B) {
	jwt := &token.JWTClaims{
		Header:  token.Header{Alg: "HS256", Kid: "keyid"},
		Payload: token.Payload{Issuer: "issuer", IssuedAt: 1234567890},
	}
	signer := &benchMockSigner{}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwt.SignedString(signer)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- ECDSA signer for realistic benchmark ---
func BenchmarkJWT_SignedString_ECDSA(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &token.SignerECDSA{
		PrivateKey: priv,
	}

	jwt := &token.JWTClaims{
		Header:  token.Header{Alg: "ES256", Kid: "keyid"},
		Payload: token.Payload{Issuer: "issuer", IssuedAt: 1234567890},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwt.SignedString(signer)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWT_SignedString_ECDSA_Parallel(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &token.SignerECDSA{
		PrivateKey: priv,
	}

	jwt := &token.JWTClaims{
		Header:  token.Header{Alg: "ES256", Kid: "keyid"},
		Payload: token.Payload{Issuer: "issuer", IssuedAt: 1234567890},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := jwt.SignedString(signer)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
