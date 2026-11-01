package execverify

import (
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newBrowserServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return testenv.NewServer(handler)
}
