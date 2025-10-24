package appleapi_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/takimoto3/appleapi-core"
)

// --- captureHandler and mocks ---

type captureHandler struct {
	logs *[]slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	*h.logs = append(*h.logs, r)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

type dummyConn struct{}

func (dummyConn) Read(b []byte) (int, error)         { return 0, nil }
func (dummyConn) Write(b []byte) (int, error)        { return len(b), nil }
func (dummyConn) Close() error                       { return nil }
func (dummyConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (dummyConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (dummyConn) SetDeadline(t time.Time) error      { return nil }
func (dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (dummyConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

// --- helper for comparing slog.Records ---

func assertRecordEqual(t *testing.T, got, want slog.Record) {
	t.Helper()

	if got.Message != want.Message {
		t.Errorf("message mismatch: got %q, want %q", got.Message, want.Message)
	}

	if got.Level != want.Level {
		t.Errorf("level mismatch: got %v, want %v", got.Level, want.Level)
	}

	gotAttrs := map[string]string{}
	got.Attrs(func(a slog.Attr) bool {
		gotAttrs[a.Key] = a.Value.String()
		return true
	})
	wantAttrs := map[string]string{}
	want.Attrs(func(a slog.Attr) bool {
		wantAttrs[a.Key] = a.Value.String()
		return true
	})

	if diff := cmp.Diff(wantAttrs, gotAttrs); diff != "" {
		t.Errorf("attributes mismatch (-want +got):\n%s", diff)
	}
}

// --- main test ---

func TestDefaultClientTrace_TableDriven(t *testing.T) {
	var logs []slog.Record
	logger := slog.New(&captureHandler{logs: &logs})
	trace := appleapi.DefaultClientTrace(logger, slog.LevelInfo)

	tests := map[string]struct {
		call func()
		want slog.Record
	}{
		"GetConn": {
			call: func() { trace.GetConn("example.com:443") },
			want: makeRecord("GetConn", slog.String("hostPort", "example.com:443")),
		},
		"GotConn": {
			call: func() {
				trace.GotConn(httptrace.GotConnInfo{
					Conn:     dummyConn{},
					Reused:   true,
					WasIdle:  true,
					IdleTime: 50 * time.Millisecond,
				})
			},
			want: makeRecord("GotConn",
				slog.String("remoteAddr", "remote"),
				slog.Bool("reused", true),
				slog.Bool("wasIdle", true),
				slog.Duration("idleTime", 50*time.Millisecond),
			),
		},
		"PutIdleConn": {
			call: func() { trace.PutIdleConn(nil) },
			want: makeRecord("PutIdleConn", slog.Any("err", nil)),
		},
		"GotFirstResponseByte": {
			call: func() { trace.GotFirstResponseByte() },
			want: makeRecord("GotFirstResponseByte"),
		},
		"Got100Continue": {
			call: func() { trace.Got100Continue() },
			want: makeRecord("Got100Continue"),
		},
		"DNSStart": {
			call: func() { trace.DNSStart(httptrace.DNSStartInfo{Host: "example.com"}) },
			want: makeRecord("DNSStart", slog.String("host", "example.com")),
		},
		"DNSDone": {
			call: func() {
				trace.DNSDone(httptrace.DNSDoneInfo{
					Addrs:     []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
					Coalesced: true,
					Err:       nil,
				})
			},
			want: makeRecord("DNSDone",
				slog.Any("addrs", []string{"127.0.0.1"}),
				slog.Any("err", nil),
				slog.Bool("coalesced", true),
			),
		},
		"ConnectStart": {
			call: func() { trace.ConnectStart("tcp", "example.com:443") },
			want: makeRecord("ConnectStart",
				slog.String("network", "tcp"),
				slog.String("addr", "example.com:443"),
			),
		},
		"ConnectDone": {
			call: func() { trace.ConnectDone("tcp", "example.com:443", nil) },
			want: makeRecord("ConnectDone",
				slog.String("network", "tcp"),
				slog.String("addr", "example.com:443"),
				slog.Any("err", nil),
			),
		},
		"TLSHandshakeStart": {
			call: func() { trace.TLSHandshakeStart() },
			want: makeRecord("TLSHandshakeStart"),
		},
		"TLSHandshakeDone": {
			call: func() { trace.TLSHandshakeDone(tls.ConnectionState{ServerName: "example.com"}, nil) },
			want: makeRecord("TLSHandshakeDone",
				slog.String("serverName", "example.com"),
				slog.Bool("handshakeComplete", false),
				slog.Any("err", nil),
			),
		},
		"WroteHeaderField": {
			call: func() { trace.WroteHeaderField("User-Agent", []string{"Go-http-client"}) },
			want: makeRecord("WroteHeaderField",
				slog.String("key", "User-Agent"),
				slog.Any("values", []string{"Go-http-client"}),
			),
		},
		"WroteRequest": {
			call: func() { trace.WroteRequest(httptrace.WroteRequestInfo{Err: nil}) },
			want: makeRecord("WroteRequest", slog.Any("err", nil)),
		},
		"Wait100Continue": {
			call: func() { trace.Wait100Continue() },
			want: makeRecord("Wait100Continue"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs = nil
			tt.call()

			if len(logs) != 1 {
				t.Fatalf("expected 1 log, got %d", len(logs))
			}

			assertRecordEqual(t, logs[0], tt.want)
		})
	}

	// contextへの紐づけ確認
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	if httptrace.ContextClientTrace(ctx) == nil {
		t.Errorf("expected ClientTrace to be stored in context")
	}
}

// helper: create expected record easily
func makeRecord(msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	r.AddAttrs(attrs...)
	return r
}
