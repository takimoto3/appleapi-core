package appleapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigureHTTPClientInitializer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Fatalf("Expected HTTP/2, got %d", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	// Solution: Get the pre-configured transport from the test server's client,
	// which is already set up to trust the server's self-signed certificate.
	serverTransport := server.Client().Transport.(*http.Transport)

	tp := MockTokenProvider{token: "Bearer MOCK_TOKEN"}
	conf := DefaultConfig()
	// Crucial fix: Assign the TLS config that trusts the test server.
	conf.TLSConfig = serverTransport.TLSClientConfig

	init := ConfigureHTTPClientInitializer(&conf)
	client, err := NewClient(init, server.URL, &tp)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	reqest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(reqest)
	if err != nil {
		t.Fatalf("Client.Do failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
