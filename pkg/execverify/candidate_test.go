package execverify

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestInstrumentDialogPayload(t *testing.T) {
	for _, input := range []string{`<img onerror=alert(1)>`, `';confirm('proof')//`, `" onmouseover="prompt(1)`} {
		value, token, err := InstrumentDialogPayload(input)
		if err != nil || !strings.HasPrefix(token, analyze.MarkerPrefix) || !strings.Contains(value, "/*"+token+"*/") {
			t.Fatalf("%q %q %v", value, token, err)
		}
		other, second, err := InstrumentDialogPayload(input)
		if err != nil || other == value || second == token {
			t.Fatal("tokens reused")
		}
	}
	if _, _, err := InstrumentDialogPayload("console.log(1)"); err == nil {
		t.Fatal("unsupported verification must be explicit")
	}
	value, token, err := InstrumentDialogPayload("alert`1`")
	if err != nil || value != "alert`"+token+"`" {
		t.Fatalf("tagged template changed shape: %s %v", value, err)
	}
	if _, _, err := InstrumentDialogPayload("alert`${arbitrary()}`"); err == nil {
		t.Fatal("unsupported interpolation instrumented")
	}
}

func TestBrowserCandidateHoverAndUnrelatedDialog(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	allowLocalVerification(t)
	for _, inert := range []bool{false, true} {
		t.Run(fmt.Sprint(inert), func(t *testing.T) {
			server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body><script>alert('unrelated')</script>`)
				for i := 0; i < 20; i++ {
					fmt.Fprint(w, `<span onmouseover="void 0">ordinary</span>`)
				}
				value := r.URL.Query().Get("q")
				if inert {
					value = html.EscapeString(value)
				}
				fmt.Fprintf(w, `<input value='%s'></body></html>`, value)
			}))
			defer server.Close()
			v, err := NewVerifier(context.Background(), 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			got, err := v.VerifyPayload(context.Background(), model.Target{URL: server.URL + "?q=test"}, "q", model.ParamQuery, "' onmouseover='alert(1)' style='display:block;width:100vw;height:100vh")
			if err != nil {
				t.Fatal(err)
			}
			if got.Executed == inert {
				t.Fatalf("unrelated dialog or missed hover: %+v", got)
			}
			if !inert && (got.Interaction != "synthetic mouseover" || !strings.HasPrefix(got.DialogMessage, analyze.MarkerPrefix) || got.VerificationPayload == "") {
				t.Fatalf("missing candidate proof: %+v", got)
			}
		})
	}
}

func TestBrowserIncompleteNavigationRejectsDialog(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	allowLocalVerification(t)
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow.png" {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>"+r.URL.Query().Get("q")+`<img src="/slow.png"></body></html>`)
	}))
	defer server.Close()
	v, err := NewVerifier(context.Background(), 6*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	got, err := v.VerifyPayload(context.Background(), model.Target{URL: server.URL}, "q", model.ParamQuery, `<script>alert(1)</script>`)
	if err == nil || got == nil || got.Executed || got.LoadError == "" {
		t.Fatalf("incomplete navigation accepted: %+v %v", got, err)
	}
}
