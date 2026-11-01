package dom

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestDataFlowFindsHiddenQueryAndStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, safe := range []bool{false, true} {
		t.Run(fmt.Sprint(safe), func(t *testing.T) {
			sink := "innerHTML"
			if safe {
				sink = "textContent"
			}
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<body><div id="out"></div><script>const params=new URLSearchParams(location.search); const q=params.get('hiddenView'); const saved=localStorage.getItem('template');function render(value){document.getElementById('out').%s=value||'';}render(q||saved);</script></body>`, sink)
			}))
			defer server.Close()
			s, err := NewScanner(context.Background(), 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			found, err := s.DetectPayloads(context.Background(), model.Target{URL: server.URL}, []string{`<img src=x onerror=alert(1)>`})
			if err != nil {
				t.Fatal(err)
			}
			if safe {
				if len(found) != 0 {
					t.Fatal(found)
				}
				return
			}
			seen := map[string]bool{}
			for _, f := range found {
				if f.ExecutionVerified {
					t.Fatal("static/runtime sink was promoted to execution proof")
				}
				for _, flow := range f.Evidence.DataFlow {
					seen[flow.Source+":"+flow.Key] = true
					if flow.Sink != "innerHTML" || flow.SourceStart < 0 || flow.SourceEnd <= flow.SourceStart {
						t.Fatal(flow)
					}
				}
			}
			if !seen["query:hiddenView"] || !seen["localStorage:template"] {
				t.Fatalf("fixed keys not reached: %+v", found)
			}
		})
	}
}

func TestPlanningFailureKeepsRuntimeMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><script>Object.defineProperty(document,'scripts',{get(){throw Error('plan read failed')}});document.body.innerHTML=decodeURIComponent(location.hash.slice(1));</script></body>`)
	}))
	defer server.Close()
	s, _ := NewScanner(context.Background(), 15*time.Second)
	defer s.Close()
	found, err := s.DetectPayloads(context.Background(), model.Target{URL: server.URL}, []string{`<img src=x onerror=alert(1)>`})
	if err == nil || !strings.Contains(err.Error(), "plan read failed") || len(found) == 0 {
		t.Fatalf("planning failure dropped runtime matrix: err=%v findings=%+v", err, found)
	}
}
