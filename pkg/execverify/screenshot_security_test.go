package execverify

import (
	"context"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestScreenshotsDisabledByDefault(t *testing.T) {
	v, err := NewVerifier(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.captureScreenshots || v.screenshotDir != "" {
		t.Fatal("default verifier created screenshot storage")
	}
	if path, err := v.saveScreenshot([]byte("synthetic")); err == nil || path != "" {
		t.Fatal("default verifier saved a screenshot")
	}
}

func TestScreenshotPrivateLifecycleAndConcurrentClose(t *testing.T) {
	v, err := NewVerifierWithOptions(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), time.Second, VerifierOptions{CaptureScreenshots: true})
	if err != nil || v.screenshotErr != nil {
		t.Fatalf("storage setup: %v %+v", err, v)
	}
	path, err := v.saveScreenshot([]byte("synthetic-png-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != v.screenshotDir {
		t.Fatal("screenshot escaped private directory")
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Go(func() {
		for range 20 {
			if _, err := v.saveScreenshot([]byte("concurrent synthetic image")); err != nil && !strings.Contains(err.Error(), "closed") {
				t.Error(err)
			}
		}
	})
	for range 4 {
		group.Go(func() {
			if err := v.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if _, err := os.Stat(v.screenshotDir); !os.IsNotExist(err) {
		t.Fatalf("screenshot directory retained: %v", err)
	}
	if _, err := v.saveScreenshot([]byte("late")); err == nil {
		t.Fatal("saved screenshot after Close")
	}
}

func TestOptInScreenshotRealChromeIsPrivateAndTemporary(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome screenshot")
	}
	allowLocalVerification(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<body>" + r.URL.Query().Get("q") + "</body>"))
	}))
	defer server.Close()
	v, err := NewVerifierWithOptions(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 15*time.Second, VerifierOptions{CaptureScreenshots: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	result, err := v.VerifyPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/?q=test"}, "q", model.ParamQuery, "<script>alert(1)</script>")
	if err != nil || !result.Executed || result.ScreenshotPath == "" {
		t.Fatalf("opt-in screenshot: %+v %v", result, err)
	}
	image, err := os.ReadFile(result.ScreenshotPath)
	if err != nil || len(image) < 8 || string(image[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("invalid PNG: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(result.ScreenshotPath); !os.IsNotExist(err) {
		t.Fatal("closed screenshot still exists")
	}
}

func TestScreenshotCancellationRemovesOnlyOwnedDirectory(t *testing.T) {
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	v, err := NewVerifierWithOptions(ctx, time.Second, VerifierOptions{CaptureScreenshots: true})
	if err != nil || v.screenshotErr != nil {
		t.Fatalf("storage setup: %v %+v", err, v)
	}
	defer v.Close()
	other, err := NewVerifierWithOptions(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), time.Second, VerifierOptions{CaptureScreenshots: true})
	if err != nil || other.screenshotErr != nil {
		t.Fatalf("independent storage: %v %+v", err, other)
	}
	defer other.Close()
	if _, err := v.saveScreenshot([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(v.screenshotDir); os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(v.screenshotDir); !os.IsNotExist(err) {
		t.Fatal("canceled screenshot retained")
	}
	if _, err := os.Stat(other.screenshotDir); err != nil {
		t.Fatal("removed another verifier's directory")
	}
}
