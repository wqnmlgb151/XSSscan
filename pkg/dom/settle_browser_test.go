package dom

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestDOMSettlingRetainsAsyncSources(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, script := range []string{
		`setTimeout(()=>document.body.innerHTML=location.hash,350)`,
		`setTimeout("document.body.innerHTML=location.hash",350)`,
		`setTimeout(()=>document.body.innerHTML=location.hash,1850)`,
		`const id=setInterval(()=>{document.body.innerHTML=location.hash;clearInterval(id)},350)`,
		`let n=0;const id=setInterval(()=>{if(++n===2){clearInterval(id);document.body.innerHTML=location.hash}},200)`,
		`let n=0;function frame(){if(++n===12)document.body.innerHTML=location.hash;else requestAnimationFrame(frame)}requestAnimationFrame(frame)`,
		`let n=0;const id=setInterval(()=>{if(++n===2){clearInterval(id);document.body.innerHTML=location.hash}},200);document.currentScript.remove()`,
		`setTimeout((a,b)=>{if(a==='keep'&&b===2)document.body.innerHTML=location.hash},350,'keep',2)`,
		`fetch('/delayed').then(r=>r.text()).then(()=>document.body.innerHTML=location.hash)`,
	} {
		t.Run(script, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/delayed" {
					time.Sleep(350 * time.Millisecond)
					fmt.Fprint(w, "done")
					return
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, "<body><script>%s</script></body>", script)
			}))
			defer server.Close()
			s, _ := NewScanner(context.Background(), 15*time.Second)
			defer s.Close()
			u, _ := url.Parse(server.URL)
			probe := buildDOMTests(u, "<img src=x onerror=alert(1)>", "xsscanAsync123")[0]
			found, err := s.runSingleDOMTest(context.Background(), model.Target{URL: server.URL}, probe, "xsscanAsync123", "<img src=x onerror=alert(1)>")
			if err != nil || len(found) == 0 {
				t.Fatalf("async source lost: %v %+v", err, found)
			}
		})
	}
}

func TestDOMExistingQueryParameterSource(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><script>document.body.innerHTML=new URLSearchParams(location.search).get('keyword')</script></body>`)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL + "?keyword=test")
	s, _ := NewScanner(context.Background(), 15*time.Second)
	defer s.Close()
	for _, probe := range buildDOMTests(u, "<img src=x onerror=alert(1)>", "xsscanQuery123") {
		if probe.Name != "search:keyword" {
			continue
		}
		found, err := s.runSingleDOMTest(context.Background(), model.Target{URL: u.String()}, probe, "xsscanQuery123", "<img src=x onerror=alert(1)>")
		if err != nil || len(found) == 0 {
			t.Fatalf("query source not tested: %v %+v", err, found)
		}
		return
	}
	t.Fatal("missing existing query test")
}
