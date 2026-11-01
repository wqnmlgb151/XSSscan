package request

import (
	"net/url"
	"testing"
)

func TestInjectPathValue_PreservesSegments(t *testing.T) {
	for _, tc := range []struct{ path, name, original, want string }{
		{"/same/same", "path[2]", "same", "/same/%3Cimg%2Fx%3E"},
		{"/a%2Fb/c", "path[2]", "c", "/a%2Fb/%3Cimg%2Fx%3E"},
		{"/api/{id}/profile", "id", "{id}", "/api/%3Cimg%2Fx%3E/profile"},
		{"/api/123/profile", "id", "123", "/api/%3Cimg%2Fx%3E/profile"},
	} {
		got, err := InjectPathValue("https://example.com"+tc.path+"?keep=1#frag", tc.name, tc.original, "<img/x>")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(got)
		if u.EscapedPath() != tc.want || u.RawQuery != "keep=1" || u.Fragment != "frag" {
			t.Fatalf("%s: %s", tc.path, got)
		}
	}
}
