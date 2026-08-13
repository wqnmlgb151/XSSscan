// Package browser provides Chrome/Chromium binary detection and graceful
// degradation for browser-dependent features (DOM XSS scan, execution
// verification, SPA rendering). Importable by cmd/ and all pkg/ packages.
package browser

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// ChromePath is an optional user-specified Chrome/Chromium binary location
// (--chrome-path flag). Empty means auto-detect.
var ChromePath string

var chromeOnce sync.Once
var chromeFound string

// candidateChromeBins are the search candidates per platform, in order.
// Mirrors chromedp's own lookup plus common distribution paths.
var candidateChromeBins = func() []string {
	bins := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"}
	if runtime.GOOS == "windows" {
		bins = append(bins,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			os.Getenv("LOCALAPPDATA")+`\Google\Chrome\Application\chrome.exe`,
		)
	}
	if runtime.GOOS == "darwin" {
		bins = append(bins,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		)
	}
	return bins
}()

// FindChrome locates a usable Chrome/Chromium binary. Returns the path or
// an error with platform-appropriate installation guidance.
func FindChrome() (string, error) {
	chromeOnce.Do(func() {
		if ChromePath != "" {
			if _, err := os.Stat(ChromePath); err == nil {
				chromeFound = ChromePath
				return
			}
		}
		for _, bin := range candidateChromeBins {
			if p, err := exec.LookPath(bin); err == nil {
				chromeFound = p
				return
			}
			if _, err := os.Stat(bin); err == nil {
				chromeFound = bin
				return
			}
		}
	})
	if chromeFound != "" {
		return chromeFound, nil
	}
	return "", fmt.Errorf("Chrome/Chromium not found. Install it or set --chrome-path:\n" +
		"  Windows: https://www.google.com/chrome/\n" +
		"  macOS:   brew install --cask google-chrome\n" +
		"  Linux:   apt install chromium-browser  (or google-chrome-stable)")
}

// EnsureChrome checks Chrome availability; the result only needs to be
// reported — features degrade gracefully when it fails.
func EnsureChrome() error {
	_, err := FindChrome()
	return err
}
