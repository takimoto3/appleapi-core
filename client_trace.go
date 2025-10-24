package appleapi

import (
	"crypto/tls"
	"log/slog"
	"net/http/httptrace"
)

func WithClientTrace(f func(*slog.Logger) *httptrace.ClientTrace) Option {
	return func(c *Client) bool {
		if c != nil {
			if tr := f(c.logger); tr != nil {
				c.trace = tr
			}
		}
		return true
	}
}

// DefaultClientTrace returns a ClientTrace with all callbacks implemented
// using the provided Logger. Unused callbacks can be set to nil by the caller.
func DefaultClientTrace(logger *slog.Logger, level slog.Level) *httptrace.ClientTrace {
	if logger == nil {
		panic("logger cannot be nil for DefaultClientTrace")
	}

	var log func(string, ...any)
	switch level {
	case slog.LevelDebug:
		log = logger.Debug
	case slog.LevelInfo:
		log = logger.Info
	case slog.LevelWarn:
		log = logger.Warn
	case slog.LevelError:
		log = logger.Error
	}

	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log("GetConn", slog.String("hostPort", hostPort))
		},

		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr := "nil"
			idleTime := info.IdleTime
			if info.Conn != nil {
				remoteAddr = info.Conn.RemoteAddr().String()
			}
			log("GotConn",
				slog.String("remoteAddr", remoteAddr),
				slog.Bool("reused", info.Reused),
				slog.Bool("wasIdle", info.WasIdle),
				slog.Duration("idleTime", idleTime),
			)
		},

		DNSStart: func(info httptrace.DNSStartInfo) {
			log("DNSStart", slog.String("host", info.Host))
		},

		DNSDone: func(info httptrace.DNSDoneInfo) {
			addrs := make([]string, len(info.Addrs))
			for i, a := range info.Addrs {
				addrs[i] = a.String()
			}
			log("DNSDone",
				slog.Any("addrs", addrs),
				slog.Any("err", info.Err),
				slog.Bool("coalesced", info.Coalesced),
			)
		},

		ConnectStart: func(network, addr string) {
			log("ConnectStart",
				slog.String("network", network),
				slog.String("addr", addr),
			)
		},

		ConnectDone: func(network, addr string, err error) {
			log("ConnectDone",
				slog.String("network", network),
				slog.String("addr", addr),
				slog.Any("err", err),
			)
		},

		TLSHandshakeStart: func() {
			log("TLSHandshakeStart")
		},

		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			log("TLSHandshakeDone",
				slog.String("serverName", state.ServerName),
				slog.Bool("handshakeComplete", state.HandshakeComplete),
				slog.Any("err", err),
			)
		},

		WroteHeaderField: func(key string, values []string) {
			log("WroteHeaderField",
				slog.String("key", key),
				slog.Any("values", values),
			)
		},

		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log("WroteRequest", slog.Any("err", info.Err))
		},

		GotFirstResponseByte: func() {
			log("GotFirstResponseByte")
		},

		Got100Continue: func() {
			log("Got100Continue")
		},
		PutIdleConn: func(err error) {
			log("PutIdleConn", slog.Any("err", err))
		},
		Wait100Continue: func() {
			log("Wait100Continue")
		},
	}
}
