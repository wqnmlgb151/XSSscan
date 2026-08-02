// Package callback provides an HTTP server for receiving blind XSS callbacks.
//
// When scanning for blind (stored) XSS, the scanner injects payloads that
// trigger the browser to send an HTTP request to a callback URL. This server
// listens for those requests and records them as evidence of exploitation.
//
// Usage:
//
//	srv := callback.NewServer(":8080")
//	srv.Start()
//	// ... inject blind payloads pointing at http://your-ip:8080/ ...
//	time.Sleep(30 * time.Second) // wait for callbacks
//	callbacks := srv.Callbacks()
//	srv.Stop()
package callback

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Callback represents a single HTTP request received from a blind XSS payload.
type Callback struct {
	Timestamp time.Time         `json:"timestamp"`
	RemoteAddr string           `json:"remote_addr"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	UserAgent string            `json:"user_agent"`
	Referer   string            `json:"referer"`
}

// Server is an HTTP server that captures blind XSS callbacks.
type Server struct {
	addr      string
	server    *http.Server
	mu        sync.Mutex
	cond      *sync.Cond
	callbacks []Callback
	listener  net.Listener
}

// NewServer creates a callback server on the given address.
// Address format: ":8080" (all interfaces) or "127.0.0.1:8080" (localhost only).
func NewServer(addr string) *Server {
	s := &Server{
		addr:      addr,
		callbacks: make([]Callback, 0),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)
	mux.HandleFunc("/health", s.handleHealth)
	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Start begins listening for callbacks in a background goroutine.
// Returns an error if the address is already in use.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("callback server listen: %w", err)
	}
	s.listener = listener
	go s.server.Serve(listener)
	return nil
}

// Addr returns the actual listening address (useful when port 0 was used for auto-assign).
func (s *Server) Addr() string {
	if s.listener == nil {
		return s.addr
	}
	return s.listener.Addr().String()
}

// BaseURL returns the full base URL for constructing callback payloads.
func (s *Server) BaseURL() string {
	addr := s.Addr()
	// Replace wildcard with localhost for payload use
	addr = strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
	addr = strings.Replace(addr, "[::]", "127.0.0.1", 1)
	return "http://" + addr
}

// Stop gracefully shuts down the server and wakes any WaitFor callers.
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	// Wake any WaitFor callers so they return immediately
	if s.cond != nil {
		s.cond.Broadcast()
	}
	return err
}

// Callbacks returns all received callbacks (thread-safe copy).
func (s *Server) Callbacks() []Callback {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Callback, len(s.callbacks))
	copy(result, s.callbacks)
	return result
}

// Count returns the number of callbacks received.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.callbacks)
}

// WaitFor blocks until at least n callbacks are received or the timeout expires.
// Uses sync.Cond for efficient notification instead of busy-polling.
// Returns whatever callbacks were received by the timeout.
func (s *Server) WaitFor(n int, timeout time.Duration) []Callback {
	s.mu.Lock()
	defer s.mu.Unlock()

	deadline := time.Now().Add(timeout)
	for len(s.callbacks) < n {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		// Use a timer channel + select so we don't need a goroutine per waiter
		timer := time.AfterFunc(remaining, func() {
			s.cond.Broadcast()
		})
		s.cond.Wait()
		timer.Stop()
	}
	result := make([]Callback, len(s.callbacks))
	copy(result, s.callbacks)
	return result
}

// Reset clears the callback history.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callbacks = s.callbacks[:0]
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Read body (limit to 1MB)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	r.Body.Close()

	// Collect headers (skip hop-by-hop)
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	cb := Callback{
		Timestamp:  time.Now(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Headers:    headers,
		Body:       string(body),
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
	}

	s.mu.Lock()
	s.callbacks = append(s.callbacks, cb)
	s.mu.Unlock()
	s.cond.Broadcast() // Wake any WaitFor callers

	// Respond with 200 OK + 1x1 transparent GIF (common callback pattern)
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	// 1x1 transparent GIF
	w.Write([]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x2c, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
		0x01, 0x00, 0x3b})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"callbacks": s.Count(),
	})
}
