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
// Contract: assign before the first FindChrome call.
var ChromePath string

var chromeOnce sync.Once
var chromeFound string
var chromeFoundErr error

// candidateChromeBins are the search candidates per platform, in order.
// Mirrors chromedp's own lookup plus Microsoft Edge (Chromium-based and the
// default browser on Windows 11).
var candidateChromeBins = func() []string {
	bins := []string{
		"google-chrome", "google-chrome-stable", "google-chrome-beta",
		"google-chrome-unstable", "chromium", "chromium-browser", "chrome",
	}
	if runtime.GOOS == "windows" {
		bins = append(bins,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			os.Getenv("LOCALAPPDATA")+`\Google\Chrome\Application\chrome.exe`,
		)
	}
	if runtime.GOOS == "darwin" {
		bins = append(bins,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		)
	}
	if runtime.GOOS == "linux" {
		bins = append(bins,
			"/usr/bin/google-chrome", "/usr/local/bin/chrome",
			"/snap/bin/chromium", "headless_shell",
		)
	}
	return bins
}()

// FindChrome locates a usable Chrome/Chromium binary. Returns the path or
// an error with platform-appropriate installation guidance.
func FindChrome() (string, error) {
	chromeOnce.Do(detectChrome)
	return chromeFound, chromeFoundErr
}

func detectChrome() {
	if ChromePath != "" {
		info, err := os.Stat(ChromePath)
		switch {
		case err != nil:
			chromeFoundErr = fmt.Errorf("--chrome-path %q is not accessible: %v", ChromePath, err)
			return
		case info.IsDir():
			chromeFoundErr = fmt.Errorf("--chrome-path %q is a directory, not an executable", ChromePath)
			return
		default:
			chromeFound = ChromePath
			return
		}
	}
	for _, bin := range candidateChromeBins {
		if p, err := exec.LookPath(bin); err == nil {
			chromeFound = p
			return
		}
		if info, err := os.Stat(bin); err == nil && !info.IsDir() {
			chromeFound = bin
			return
		}
	}
	chromeFoundErr = fmt.Errorf("Chrome/Chromium not found. Install it or set --chrome-path:\n" +
		"  Windows: https://www.google.com/chrome/  (or Microsoft Edge, Chromium-based)\n" +
		"  macOS:   brew install --cask google-chrome\n" +
		"  Linux:   apt install chromium  (or google-chrome-stable / snap chromium)")
}

// EnsureChrome checks Chrome availability; the result only needs to be
// reported — features degrade gracefully when it fails.
func EnsureChrome() error {
	_, err := FindChrome()
	return err
}
