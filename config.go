package appleapi

import (
	"crypto/tls"
	"time"
)

// Default global configuration for all clients.
var defaultConfig = &HTTPConfig{
	DialTimeout:         30 * time.Second, // Timeout for establishing TCP connections
	KeepAlive:           30 * time.Second, // Interval for TCP keep-alive probes
	IdleConnTimeout:     90 * time.Second, // Max idle time before closing a keep-alive connection
	MaxConnsPerHost:     30,               // Maximum total connections (idle + active) per host
	MaxIdleConnsPerHost: 30,               // Maximum idle connections per host
	ReadIdleTimeout:     15 * time.Second, // Idle period before sending an HTTP/2 PING
	HTTPTimeout:         60 * time.Second, // Overall HTTP request timeout (connect + transfer + response)
	TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, // Require TLS 1.3 for secure connections
	},
}

// HTTPConfig defines transport and timeout settings used by clients.
type HTTPConfig struct {
	HTTPTimeout         time.Duration // Maximum duration for a complete HTTP request
	ReadIdleTimeout     time.Duration // Idle period before sending an HTTP/2 PING frame
	KeepAlive           time.Duration // Interval for TCP keep-alive probes
	DialTimeout         time.Duration // Timeout for establishing new TCP connections
	MaxConnsPerHost     int           // Maximum total connections per host (idle + active)
	IdleConnTimeout     time.Duration // Max time an idle connection is kept alive
	MaxIdleConnsPerHost int           // Maximum idle connections per host
	TLSConfig           *tls.Config   // TLS settings for HTTPS connections
}

// GetDefaultConfigValue returns a copy of the default configuration.
// The returned configuration is independent, and modifications to it
// will not affect the package's internal state.
func DefaultConfig() HTTPConfig {
	// Create a shallow copy of the struct
	configCopy := *defaultConfig
	// If TLSConfig is not nil, clone it to ensure a deep copy
	if defaultConfig.TLSConfig != nil {
		configCopy.TLSConfig = defaultConfig.TLSConfig.Clone()
	}
	return configCopy
}
