package execverify

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"

	"github.com/xsscan/xsscan/pkg/model"
)

// capturedTarget replays the actual authenticated request, including refreshed
// CSRF headers, rather than reconstructing it from stale CLI state.
func capturedTarget(exchange *model.HTTPExchange, fallback model.Target) (model.Target, error) {
	if exchange == nil || exchange.Request == "" {
		return fallback, nil
	}
	if exchange.InitialRequest != "" {
		initial := *exchange
		initial.URL, initial.Request, initial.RequestTruncated = exchange.InitialURL, exchange.InitialRequest, exchange.InitialRequestTruncated
		exchange = &initial
	}
	if exchange.RequestTruncated {
		return fallback, fmt.Errorf("execution replay unavailable: captured request body truncated")
	}
	head, body, ok := strings.Cut(exchange.Request, "\r\n\r\n")
	if !ok {
		return fallback, fmt.Errorf("captured request has no header separator")
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(head + "\r\n\r\n")))
	if err != nil {
		return fallback, fmt.Errorf("parse captured request: %w", err)
	}
	defer req.Body.Close()
	// The exchange URL contains the original scheme and authority; the HTTP
	// request line preserves its encoded path/query. Host is forwarded separately.
	base, err := http.NewRequest(req.Method, exchange.URL, nil)
	if err != nil {
		return fallback, fmt.Errorf("captured request URL: %w", err)
	}
	if !strings.EqualFold(req.Host, base.URL.Host) {
		return fallback, fmt.Errorf("execution replay unavailable: custom Host %q differs from URL authority %q", req.Host, base.URL.Host)
	}
	base.URL.Path, base.URL.RawPath, base.URL.RawQuery = req.URL.Path, req.URL.RawPath, req.URL.RawQuery
	out := model.Target{URL: base.URL.String(), Method: req.Method, Body: body, Headers: make(map[string]string)}
	for key, values := range req.Header {
		out.Headers[key] = strings.Join(values, ", ")
	}
	// Chrome owns Host/:authority and rejects an explicit Host override.
	delete(out.Headers, "Content-Length")
	delete(out.Headers, "Transfer-Encoding")
	delete(out.Headers, "Proxy-Authorization")
	return out, nil
}
