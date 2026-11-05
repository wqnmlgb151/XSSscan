package execverify

import (
	"context"
	"errors"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
	"time"
)

func TestVerificationLateBoundBrowserBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome")
	}
	allowLocalVerification(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="icon" href="data:,"><script src="/resource"></script><body>ok</body></html>`))
	}))
	defer server.Close()
	v, err := NewVerifier(context.Background(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m := requestbudget.New(0, 1)
	_, err = v.VerifyPayload(requestbudget.WithMeter(context.Background(), m), model.Target{URL: server.URL + "?q=x"}, "q", model.ParamQuery, "<script>alert(1)</script>")
	if !errors.Is(err, requestbudget.ErrBrowser) || m.Browser.Count() != 1 {
		t.Fatalf("late bound verifier budget: count=%d err=%v", m.Browser.Count(), err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
}
