package execverify

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestTaggedDialogRealChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if r.URL.Path == "/inert" {
			q = "let x=`" + strings.ReplaceAll(q, "`", "\\`") + "`;"
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><script>"+q+"</script></body></html>")
	}))
	defer server.Close()
	v, err := NewVerifier(context.Background(), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, path := range []string{"active", "inert"} {
		result, err := v.VerifyPayload(context.Background(), model.Target{URL: server.URL + "/" + path + "?q=x"}, "q", model.ParamQuery, "alert`1`")
		if err != nil {
			t.Fatal(err)
		}
		if result.Executed != (path == "active") {
			t.Fatalf("%s tagged template execution mismatch: %+v", path, result)
		}
		if !strings.Contains(result.VerificationPayload, "alert`") || strings.Contains(result.VerificationPayload, "alert(") {
			t.Fatal("changed tagged payload into call")
		}
	}
}
