package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"
)

// newTestProvider creates a TokenProvider instance for benchmarking.
// It generates a temporary ECDSA key and applies the specified TTL.
func newTestProvider(b *testing.B, ttl time.Duration) *TokenProvider {
	b.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	p := NewProvider(
		"test-key-id",
		"test-team-id",
		priv,
		WithTTL(ttl),
	)

	return p.(*TokenProvider)
}

// 1. Cache-hit performance
// Measures the cost of retrieving a token when the cache is valid.
func BenchmarkToken_CacheHit(b *testing.B) {
	p := newTestProvider(b, time.Minute)

	now := time.Now()

	// Warm up cache
	if _, err := p.GetToken(now); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := p.GetToken(now); err != nil {
			b.Fatal(err)
		}
	}
}

// 2. Always expired (measures signing cost)
// Forces token regeneration on every call.
func BenchmarkToken_AlwaysRefresh(b *testing.B) {
	p := newTestProvider(b, time.Nanosecond)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Strictly increasing timestamp guarantees expiration
		now := time.Unix(0, int64(i+1))
		if _, err := p.GetToken(now); err != nil {
			b.Fatal(err)
		}
	}
}

// 3. Parallel access performance
// Measures concurrent access under cache-hit conditions.
func BenchmarkToken_Parallel(b *testing.B) {
	p := newTestProvider(b, time.Minute)

	now := time.Now()

	// Warm up cache
	if _, err := p.GetToken(now); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.GetToken(now); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// 4. Parallel refresh (double-check locking validation)
// Forces expiration and measures lock contention behavior.
func BenchmarkToken_ParallelRefresh(b *testing.B) {
	p := newTestProvider(b, time.Nanosecond)

	var counter int64

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := atomic.AddInt64(&counter, 1)
			now := time.Unix(0, n) // guarantees expiration
			if _, err := p.GetToken(now); err != nil {
				b.Fatal(err)
			}
		}
	})
}
