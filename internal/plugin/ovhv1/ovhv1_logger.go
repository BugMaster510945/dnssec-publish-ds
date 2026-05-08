package ovhv1

import (
	"log/slog"
	"net/http"
)

func (p *OVHv1Plugin) logger() *slog.Logger {
	if p.log != nil {
		return p.log
	}
	return slog.Default()
}

func (p *OVHv1Group) logger() *slog.Logger {
	if p.log != nil {
		return p.log
	}
	return slog.Default()
}

// ovhSlogLogger adapts a *slog.Logger to the ovh.Logger interface
// (LogRequest / LogResponse).
type ovhSlogLogger struct {
	log *slog.Logger
}

func (l ovhSlogLogger) logger() *slog.Logger {
	if l.log != nil {
		return l.log
	}
	return slog.Default()
}

func (l ovhSlogLogger) LogRequest(req *http.Request) {
	if req == nil {
		return
	}
	l.logger().Debug("ovh_http_request",
		"method", req.Method,
		"url", req.URL.String(),
		"content_length", req.ContentLength,
	)
}

func (l ovhSlogLogger) LogResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	l.logger().Debug("ovh_http_response",
		"status", resp.Status,
		"status_code", resp.StatusCode,
		"content_length", resp.ContentLength,
		"query_id", resp.Header.Get("X-Ovh-Queryid"),
	)
}
