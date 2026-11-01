package httpclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/xsscan/xsscan/pkg/model"
)

const MaxEvidenceBody = 512 * 1024

type recordKey struct{}
type attachedKey struct{}
type redirectKey struct{}

type Capture struct {
	mu                         sync.Mutex
	exchange                   model.HTTPExchange
	requestHead, responseHead  string
	requestBody, responseBody  []byte
	read                       int64
	complete                   bool
	initialURL, initialRequest string
	initialTruncated           bool
}

// RecordContext lets an authentication failure retain its last exchange.
func RecordContext(ctx context.Context) (context.Context, *Capture) {
	c := &Capture{}
	return context.WithValue(ctx, recordKey{}, c), c
}
func (c *Capture) Snapshot() model.HTTPExchange {
	if c == nil {
		return model.HTTPExchange{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.exchange
	out.InitialURL, out.InitialRequest, out.InitialRequestTruncated = c.initialURL, c.initialRequest, c.initialTruncated
	if model.NeedsBinaryEvidence(out.InitialRequest) {
		out.InitialRequestBase64 = base64.StdEncoding.EncodeToString([]byte(out.InitialRequest))
	}
	out.Request = c.requestHead + string(c.requestBody)
	out.Response = c.responseHead + string(c.responseBody)
	if model.NeedsBinaryEvidence(out.Request) {
		out.RequestBase64 = base64.StdEncoding.EncodeToString([]byte(out.Request))
	}
	if model.NeedsBinaryEvidence(out.Response) {
		out.ResponseBase64 = base64.StdEncoding.EncodeToString([]byte(out.Response))
	}
	out.ResponseIncomplete = c.responseHead != "" && !c.complete
	return out
}
func Captured(resp *http.Response) model.HTTPExchange {
	if resp == nil || resp.Request == nil {
		return model.HTTPExchange{}
	}
	c, _ := resp.Request.Context().Value(recordKey{}).(*Capture)
	return c.Snapshot()
}

// CaptureSummary identifies the final captured request without copying response
// bodies or encoding binary evidence. A truncated digest covers the saved prefix.
type CaptureSummary struct {
	RequestDigest      string
	RequestTruncated   bool
	ResponseIncomplete bool
}

func CapturedSummary(resp *http.Response) CaptureSummary {
	if resp == nil || resp.Request == nil {
		return CaptureSummary{}
	}
	c, _ := resp.Request.Context().Value(recordKey{}).(*Capture)
	if c == nil {
		return CaptureSummary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := CaptureSummary{RequestTruncated: c.exchange.RequestTruncated, ResponseIncomplete: c.responseHead != "" && !c.complete}
	if c.requestHead != "" {
		h := sha256.New()
		h.Write([]byte(c.requestHead))
		h.Write(c.requestBody)
		out.RequestDigest = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

// WithCapture records after net/http adds cookie-jar values. Neither credentials
// nor payloads are redacted. The original client and request are never mutated.
// This is in-memory replay evidence; report.Reporter redacts the export projection
// by default. Do not serialize captures directly to a shareable report.
func WithCapture(client *http.Client) *http.Client {
	copy := *client
	if _, ok := copy.Transport.(captureTransport); !ok {
		copy.Transport = captureTransport{base: copy.Transport}
		previous := copy.CheckRedirect
		copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if previous != nil {
				if err := previous(req, via); err != nil {
					return err
				}
			} else if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if req.Response != nil && req.Response.Request != nil {
				if c, ok := req.Response.Request.Context().Value(recordKey{}).(*Capture); ok {
					*req = *req.WithContext(context.WithValue(context.WithValue(req.Context(), recordKey{}, c), redirectKey{}, true))
				}
			}
			return nil
		}
	}
	return &copy
}

type captureTransport struct{ base http.RoundTripper }

func (t captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Context().Value(attachedKey{}) != nil {
		return base.RoundTrip(req)
	}
	c, _ := req.Context().Value(recordKey{}).(*Capture)
	if c == nil {
		c = &Capture{}
	}
	ctx := context.WithValue(context.WithValue(req.Context(), recordKey{}, c), attachedKey{}, true)
	copy := req.Clone(ctx)
	c.mu.Lock()
	if req.Context().Value(redirectKey{}) == nil {
		c.initialURL, c.initialRequest, c.initialTruncated = "", "", false
	}
	if req.Context().Value(redirectKey{}) != nil && c.requestHead != "" && c.initialRequest == "" {
		c.initialURL, c.initialRequest, c.initialTruncated = c.exchange.URL, c.requestHead+string(c.requestBody), c.exchange.RequestTruncated
	}
	c.exchange = model.HTTPExchange{URL: req.URL.String()}
	c.requestHead = requestHead(req)
	c.responseHead = ""
	c.requestBody = nil
	c.responseBody = nil
	c.read = 0
	c.complete = false
	c.mu.Unlock()
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("record request body: %w", err)
		}
		prefix, err := io.ReadAll(io.LimitReader(body, MaxEvidenceBody+1))
		body.Close()
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.exchange.RequestTruncated = len(prefix) > MaxEvidenceBody
		c.requestBody = prefix[:min(len(prefix), MaxEvidenceBody)]
		c.mu.Unlock()
	} else if copy.Body != nil && copy.Body != http.NoBody {
		copy.Body = &captureBody{ReadCloser: copy.Body, capture: c, request: true}
	}
	resp, err := base.RoundTrip(copy)
	if resp != nil {
		resp.Request = copy
		c.mu.Lock()
		c.responseHead = responseHead(resp)
		c.complete = resp.Body == nil || resp.Body == http.NoBody
		c.mu.Unlock()
		if resp.Body != nil {
			resp.Body = &captureBody{ReadCloser: resp.Body, capture: c, length: resp.ContentLength}
		}
	}
	return resp, err
}

type captureBody struct {
	io.ReadCloser
	capture *Capture
	request bool
	length  int64
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	c := b.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	if b.request {
		available := MaxEvidenceBody - len(c.requestBody)
		c.requestBody = append(c.requestBody, p[:min(n, available)]...)
		if n > available {
			c.exchange.RequestTruncated = true
		}
	} else {
		available := MaxEvidenceBody - len(c.responseBody)
		c.responseBody = append(c.responseBody, p[:min(n, available)]...)
		c.read += int64(n)
		if n > available {
			c.exchange.ResponseTruncated = true
		}
		if err == io.EOF || (b.length >= 0 && c.read >= b.length) {
			c.complete = true
		}
	}
	return n, err
}
func requestHead(req *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Host)
	headers := req.Header.Clone()
	if _, ok := headers["User-Agent"]; !ok {
		headers.Set("User-Agent", "Go-http-client/1.1")
	}
	if req.ContentLength > 0 {
		headers.Set("Content-Length", fmt.Sprint(req.ContentLength))
	}
	writeHeaders(&b, headers)
	b.WriteString("\r\n")
	return b.String()
}
func responseHead(resp *http.Response) string {
	var b strings.Builder
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %s\r\n", proto, status)
	writeHeaders(&b, resp.Header)
	b.WriteString("\r\n")
	return b.String()
}
func writeHeaders(b *strings.Builder, headers http.Header) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range headers[key] {
			fmt.Fprintf(b, "%s: %s\r\n", key, value)
		}
	}
}
