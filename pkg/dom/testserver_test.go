package dom

import (
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newBrowserServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return testenv.NewServer(handler)
}
