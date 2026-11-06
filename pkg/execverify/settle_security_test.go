package execverify

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestInertVerificationSettlesBeforeFullWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	var requests atomic.Int64
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<link rel=icon href="data:,"><body>`+html.EscapeString(r.URL.Query().Get("q"))+`</body>`)
	}))
	defer server.Close()
	ctx := ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true})
	legacy := os.Getenv("XSSCAN_TEST_FULL_WINDOW") == "1"
	ctx = browser.WithFullVerificationWindow(ctx, legacy)
	verifier, err := NewVerifier(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	target := model.Target{URL: server.URL + "/?q=x"}
	if _, err := verifier.VerifyPayload(ctx, target, "q", model.ParamQuery, `<script>alert(1)</script>`); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		before := requests.Load()
		start := time.Now()
		result, err := verifier.VerifyPayload(ctx, target, "q", model.ParamQuery, `<script>alert(1)</script>`)
		elapsed := time.Since(start)
		t.Logf("SETTLE_BASELINE inert round=%d duration_ms=%.3f requests=%d", round, float64(elapsed)/float64(time.Millisecond), requests.Load()-before)
		if err != nil || result.Executed {
			t.Fatalf("inert verdict changed: %+v %v", result, err)
		}
		if !legacy && elapsed >= 2*time.Second {
			t.Errorf("inert page unnecessarily retained full window: %s", elapsed)
		}
	}
}

func TestVerificationActivityBoundsAndCancellation(t *testing.T) {
	activity := newVerificationActivity(context.Background())
	for i := 0; i < 5000; i++ {
		activity.observe(&network.EventRequestWillBeSent{RequestID: network.RequestID(fmt.Sprint(i))})
	}
	if len(activity.pending) != 4096 || !activity.overflow {
		t.Fatal("network observation must be bounded and conservative on overflow")
	}
	for i := 0; i < 5000; i++ {
		activity.observe(&network.EventLoadingFinished{RequestID: network.RequestID(fmt.Sprint(i))})
	}
	if len(activity.pending) != 0 || !activity.overflow {
		t.Fatal("overflow must not manufacture inertness")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := activity.wait(ctx, make(chan dialogInfo)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel lost: %v", err)
	}
	activity = newVerificationActivity(browser.WithFullVerificationWindow(context.Background(), true))
	dialogs := make(chan dialogInfo, 1)
	dialogs <- dialogInfo{dialogType: "alert", message: "candidate"}
	proof, err := activity.wait(context.Background(), dialogs)
	if err != nil || proof == nil || proof.message != "candidate" {
		t.Fatal("dialog event lost")
	}
}

func TestStaticVerificationInertnessIsConservative(t *testing.T) {
	for _, row := range []struct {
		document string
		inert    bool
	}{
		{`<html><body><p>&lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>`, true},
		{`<div><input value="ordinary"><span>text</span></div>`, true},
		{`<script>Element.prototype.matches=()=>false</script>`, false},
		{`<template shadowrootmode="open"><img onerror="alert(1)"></template>`, false},
		{`<svg><set attributeName="onmouseover" to="alert(1)"></set></svg>`, false},
		{`<meta http-equiv="refresh" content="2;url=/execute">`, false},
		{`<input onfocus="alert(1)">`, false},
		{"<a href='java\nscript:alert(1)'>link</a>", false},
		{`<custom-element>unknown</custom-element>`, false},
	} {
		if got := inertVerificationDocument([]byte(row.document)); got != row.inert {
			t.Errorf("inert classification %v want%v: %s", got, row.inert, row.document)
		}
	}
}

func TestVerificationBodyEligibilityRequiresBoundedDecodedBytes(t *testing.T) {
	activity := newVerificationActivity(context.Background())
	id := network.RequestID("document")
	activity.observe(&network.EventResponseReceived{RequestID: id, Type: network.ResourceTypeDocument, Response: &network.Response{MimeType: "text/html"}})
	if activity.sourceEligible() {
		t.Fatal("unfinished/unknown body eligible")
	}
	activity.observe(&network.EventDataReceived{RequestID: id, DataLength: 256 * 1024})
	if activity.sourceEligible() {
		t.Fatal("unfinished body eligible")
	}
	activity.observe(&network.EventLoadingFinished{RequestID: id})
	if !activity.sourceEligible() {
		t.Fatal("bounded decoded body rejected")
	}
	activity.observe(&network.EventDataReceived{RequestID: id, DataLength: 1})
	if activity.sourceEligible() {
		t.Fatal("oversized decoded body eligible")
	}
	unknown := newVerificationActivity(context.Background())
	unknown.observe(&network.EventResponseReceived{RequestID: id, Type: network.ResourceTypeDocument, Response: &network.Response{MimeType: "text/html", Headers: network.Headers{"Refresh": "2;url=/later"}}})
	unknown.observe(&network.EventDataReceived{RequestID: id, DataLength: 10})
	unknown.observe(&network.EventLoadingFinished{RequestID: id})
	if unknown.sourceEligible() {
		t.Fatal("Refresh response eligible")
	}
}

func TestLegacyFullVerificationWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	ctx := browser.WithFullVerificationWindow(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), true)
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>inert</body>")
	}))
	defer server.Close()
	verifier, err := NewVerifier(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	start := time.Now()
	result, err := verifier.VerifyPayload(ctx, model.Target{URL: server.URL + "/?q=x"}, "q", model.ParamQuery, `<script>alert(1)</script>`)
	if err != nil || result.Executed || time.Since(start) < 3*time.Second {
		t.Fatalf("legacy observation contract changed: %+v %v", result, err)
	}
}

func TestVerificationRetainsTwoPointFiveSecondHandlers(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	ctx := ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true})
	verifier, err := NewVerifier(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<link rel=icon href="data:,"><body><script>const candidate=new URLSearchParams(location.search).get('q');setTimeout(()=>document.body.insertAdjacentHTML('beforeend',candidate),2500);</script></body>`)
	}))
	defer server.Close()
	for _, event := range []string{"onfocus", "onmouseover"} {
		t.Run(event, func(t *testing.T) {
			result, err := verifier.VerifyPayload(ctx, model.Target{URL: server.URL + "/?q=x"}, "q", model.ParamQuery, "<input "+event+"=alert(1)>")
			if err != nil || !result.Executed {
				t.Fatalf("late %s handler lost: %+v %v", event, result, err)
			}
		})
	}
}

func TestVerificationRetainsHiddenAndTamperedExecutables(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	ctx := ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true})
	verifier, err := NewVerifier(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		candidate := r.URL.Query().Get("q")
		if r.URL.Path == "/refresh" {
			w.Header().Set("Refresh", "2.5; url=/execute?q="+url.QueryEscape(candidate))
			fmt.Fprint(w, "<body>waiting</body>")
			return
		}
		if r.URL.Path == "/execute" {
			fmt.Fprint(w, "<body><script>"+candidate+"</script></body>")
			return
		}
		if r.URL.Path == "/shadow" {
			fmt.Fprintf(w, `<link rel=icon href="data:,"><body><div><template shadowrootmode="open"><img src="/missing" onerror="setTimeout(()=>%s,2500)"></template></div></body>`, candidate)
			return
		}
		fmt.Fprintf(w, `<link rel=icon href="data:,"><body><script>Element.prototype.matches=()=>false;Element.prototype.querySelectorAll=()=>[];setTimeout(()=>%s,2500)</script></body>`, candidate)
	}))
	defer server.Close()
	for _, path := range []string{"/shadow", "/prototype", "/refresh"} {
		t.Run(path[1:], func(t *testing.T) {
			result, err := verifier.VerifyPayload(ctx, model.Target{URL: server.URL + path + "?q=x"}, "q", model.ParamQuery, `alert(1)`)
			if err != nil || !result.Executed {
				t.Fatalf("late executable classified inert: %+v %v", result, err)
			}
		})
	}
}
