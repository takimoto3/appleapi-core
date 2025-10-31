# appleapi-core

`appleapi-core` is a lightweight Go library providing the foundational components for authenticating with Apple's JWT-secured APIs (such as APNs or DeviceCheck).  
It offers a reusable HTTP client that automatically handles token generation, caching, and signing.

## Design Philosophy

This library is designed as a core building block for interacting with Apple’s JWT-based services.  
It provides the fundamental mechanisms for authentication and HTTP communication, intended to be embedded or wrapped by higher-level, service-specific clients (for example, a client for the App Store Connect API or the Apple Music API).

These wrapper clients are responsible for implementing specific API endpoints and business logic, while `appleapi-core` manages the authentication token lifecycle and underlying HTTP transport.  
The `Host` field in the `Client` serves as a convenience mechanism for higher-level API clients, allowing them to define a consistent base endpoint for Apple service requests.

This separation keeps the core library clean, reusable, and focused on authentication and transport concerns.

## Features

- Automatic JWT generation and caching with `TokenProvider`.
- Configurable HTTP/2 client built on Go’s standard `http.Transport`.
- Supports `.p8` private keys (PKCS#8) for token signing.
- Minimal external dependencies.
- Clean, modular design separating token generation from the HTTP client.

## Installation

```bash
go get github.com/takimoto3/appleapi-core
```

## Usage

The following example demonstrates how to create a client and make a request to an Apple API.

```go
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/takimoto3/appleapi-core"
	"github.com/takimoto3/appleapi-core/token"
)

func main() {
	// Your Apple Developer credentials
	keyID := "YOUR_KEY_ID"
	teamID := "YOUR_TEAM_ID"
	pkcs8FilePath := "/path/to/your/AuthKey.p8"

	// 1. Load your private key
	privateKey, err := token.LoadPKCS8File(pkcs8FilePath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	// 2. Create a TokenProvider
	// It is recommended to pass a logger for better visibility.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tp := token.NewProvider(keyID, teamID, privateKey, token.WithLogger(logger))

	// 3. Create the appleapi Client
	// The host parameter is optional and can be left empty if not needed.
	client, err := appleapi.NewClient(appleapi.DefaultHTTPClientInitializer(), "", tp, appleapi.WithLogger(logger))
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.CloseIdleConnections()

	// 4. Create and execute a request
	// The client automatically adds the "Authorization: Bearer <token>" header.
	req, err := http.NewRequest("GET", "https://api.some-apple-service.com/v1/some/endpoint", nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Check the response
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	fmt.Printf("Request successful! Status: %s\n", resp.Status)
	// ... process response body
}
```

## Advanced Usage: Client Tracing

This feature leverages Go’s `net/http/httptrace` package to provide detailed insight into the client’s HTTP lifecycle (DNS resolution, TLS handshake, connection reuse, and more).

You can enable detailed request lifecycle logging by using the `WithClientTrace` option.  
The `DefaultClientTrace` helper provides an easy way to enable default tracing with your logger.

```go
// (Inside main function, after logger is created)

// 3. Create the appleapi Client with tracing
// DefaultClientTrace provides a pre-configured trace that logs to the client's logger.
client, err := appleapi.NewClient(appleapi.DefaultHTTPClientInitializer(), "", tp,
    appleapi.WithLogger(logger),
    appleapi.WithClientTrace(func(l *slog.Logger) *httptrace.ClientTrace {
        // The log level can be slog.LevelDebug, slog.LevelInfo, etc.
        return appleapi.DefaultClientTrace(l, slog.LevelDebug)
    }),
)
if err != nil {
    log.Fatalf("failed to create client: %v", err)
}
defer client.CloseIdleConnections()

// Now, when you make a request with this client,
// detailed trace logs will be output.
resp, err := client.Do(req)
if err != nil {
    log.Fatalf("request failed: %v", err)
}
```

**Example trace output:**
```
level=DEBUG msg="DNS Start" host="api.some-apple-service.com"
level=DEBUG msg="DNS Done" addrs="[203.0.113.42]"
level=DEBUG msg="Connect Start" network="tcp" addr="203.0.113.42:443"
level=DEBUG msg="Connect Done" network="tcp" addr="203.0.113.42:443" err="<nil>"
level=DEBUG msg="Got First Response Byte"
```

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
