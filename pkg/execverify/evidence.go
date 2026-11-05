package execverify

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/internal/request"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// capturedTarget replays the actual authenticated request, including refreshed
// CSRF headers, rather than reconstructing it from stale CLI state.
func capturedTarget(exchange *model.HTTPExchange, fallback model.Target) (model.Target, error) {
	fallback.Headers = request.CloneHeaders(fallback.Headers)
	fallback.Cookies = request.CloneCookies(fallback.Cookies)
	if exchange == nil || (exchange.Request == "" && exchange.InitialRequest == "") {
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
	// Captures retain entity bytes, not a chunked wire stream. Never forward
	// framing bytes as application data or silently replay a partial entity.
	if len(req.TransferEncoding) != 0 {
		return fallback, fmt.Errorf("execution replay unavailable: captured transfer encoding is unsupported")
	}
	if req.Header.Get("Content-Length") != "" && req.ContentLength != int64(len(body)) {
		return fallback, fmt.Errorf("execution replay unavailable: captured body length differs from Content-Length")
	}
	if req.URL.IsAbs() || !strings.HasPrefix(req.RequestURI, "/") {
		return fallback, fmt.Errorf("execution replay unavailable: captured request target must be origin-form")
	}
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
	base.URL.ForceQuery = req.URL.ForceQuery
	base.URL.Fragment, base.URL.RawFragment = "", ""
	out := model.Target{URL: base.URL.String(), Method: req.Method, Body: body, Headers: make(map[string]string)}
	for key, values := range req.Header {
		separator := ", "
		if key == "Cookie" {
			separator = "; "
		}
		out.Headers[key] = strings.Join(values, separator)
	}
	// Chrome owns Host/:authority and rejects an explicit Host override.
	delete(out.Headers, "Content-Length")
	delete(out.Headers, "Transfer-Encoding")
	delete(out.Headers, "Proxy-Authorization")
	return out, nil
}
