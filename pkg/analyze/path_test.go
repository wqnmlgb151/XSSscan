package analyze

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestExtractPathParams_EncodedSlashIndexes(t *testing.T) {
	target := "https://example.com/a%2Fb/name%21"
	params := extractPathParams(target)
	found := false
	for _, param := range params {
		if param.Value != "name!" {
			continue
		}
		found = true
		if param.Name != "path[2]" {
			t.Fatalf("Wrong segment index: %+v", param)
		}
		got, err := request.InjectPathValue(target, param.Name, param.Value, "proof")
		if err != nil || got != "https://example.com/a%2Fb/proof" {
			t.Fatalf("Wrong injected path: %s, %v", got, err)
		}
	}
	if !found {
		t.Fatal("Dynamic path parameter not discovered")
	}
}

func TestAnalyze_PathMarkerAttribution(t *testing.T) {
	previous := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = previous })
	for _, path := range []string{"/fixed/a%2Fb/name%21", "/fixed/{slug}", "/fixed/:slug"} {
		t.Run(path, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				segments := strings.Split(r.URL.EscapedPath(), "/")
				fmt.Fprint(w, "<p>"+segments[len(segments)-1]+"</p>")
			}))
			defer server.Close()
			target := model.Target{URL: server.URL + path}
			result, err := NewAnalyzer(server.Client()).Analyze(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.InjectionPoints) != 1 || result.InjectionPoints[0].Parameter.Type != model.ParamPath {
				t.Fatalf("missing path reflection: %+v", result.InjectionPoints)
			}
			if result.Target.URL != target.URL {
				t.Fatal("original URL changed")
			}
		})
	}
}

func TestInjectPerParamMarkers_PathIsolation(t *testing.T) {
	target := model.Target{URL: "https://example.com/fixed/a%2Fb/name%21?q=keep#fragment"}
	markers := map[string]string{paramKey(model.Parameter{Name: "path[3]", Type: model.ParamPath}): "proof"}
	got := injectPerParamMarkers(target, markers, false)
	if got.URL != "https://example.com/fixed/a%2Fb/proof?q=keep#fragment" {
		t.Fatal(got.URL)
	}
}

func TestInjectPerParamMarkers_RepeatedPathValues(t *testing.T) {
	target := model.Target{URL: "https://example.com/fixed/name%21/name%21"}
	markers := map[string]string{paramKey(model.Parameter{Name: "path[2]", Type: model.ParamPath}): "first", paramKey(model.Parameter{Name: "path[3]", Type: model.ParamPath}): "second"}
	got := injectPerParamMarkers(target, markers, false)
	if got.URL != "https://example.com/fixed/first/second" {
		t.Fatal(got.URL)
	}
}

func TestAnalyze_PathWAFPerParameterFallback(t *testing.T) {
	previous := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = previous })
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Count(r.URL.Path, MarkerPrefix) > 1 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "request blocked by cloudflare")
			return
		}
		fmt.Fprint(w, "<p>"+r.URL.Path+"</p>")
	}))
	defer server.Close()
	result, err := NewAnalyzer(server.Client()).Analyze(context.Background(), model.Target{URL: server.URL + "/fixed/name%21/other%21"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.InjectionPoints) != 2 {
		t.Fatalf("path WAF fallback lost reflections: %+v", result.InjectionPoints)
	}
}
