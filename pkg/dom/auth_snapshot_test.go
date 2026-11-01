package dom

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestScannerAuthSnapshotDoesNotFollowCallerMutations(t *testing.T) {
	input := &AuthState{Cookies: []*http.Cookie{{Name: "session", Value: "original", Unparsed: []string{"original"}}, nil}}
	s, err := NewScannerWithAuth(context.Background(), time.Second, input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input.Cookies[0].Value = "other"
	input.Cookies[0].Unparsed[0] = "other"
	input.Cookies[1] = &http.Cookie{Name: "extra", Value: "other"}
	if s.auth.Cookies[0].Value != "original" || s.auth.Cookies[0].Unparsed[0] != "original" || s.auth.Cookies[1] != nil {
		t.Fatal("DOM scanner identity changed with caller-owned cookies")
	}
}
