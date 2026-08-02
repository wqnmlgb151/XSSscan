package analyze

import (
	"net/http"
	"testing"
)

// TestFrameworkDetectReact verifies React detection via react-root and
// data-reactroot markers.
func TestFrameworkDetectReact(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantName string
		wantConf float64
	}{
		{"react-root", `<div id="react-root"></div>`, "React", 0.25},
		{"react-dom", `<script src="react-dom.js"></script>`, "React", 0.25},
		{"data-reactroot", `<div data-reactroot="">app</div>`, "React", 0.25},
		{"multiple indicators", `<div id="react-root" data-reactroot="x"></div><script src="react-dom.js"></script>`, "React", 0.75},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == tt.wantName {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected framework %s to be detected, got %v", tt.wantName, results)
			}
		})
	}
}

// TestFrameworkDetectVue verifies Vue.js detection.
func TestFrameworkDetectVue(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		{"vue.js", `<script src="vue.js"></script>`, 0.25},
		{"vue.min.js", `<script src="vue.min.js"></script>`, 0.25},
		{"data-v- attribute", `<div data-v-a1b2c3d4="true"></div>`, 0.25},
		{"__VUE__", `<script>window.__VUE__={}</script>`, 0.25},
		{"two indicators", `<script src="vue.min.js"></script><div data-v-abcdef12></div>`, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "Vue" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected Vue framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectAngular verifies Angular detection including both AngularJS
// 1.x (ng-app, ng-controller) and Angular 2+ (ng-version) indicators.
func TestFrameworkDetectAngular(t *testing.T) {
	fd := NewFrameworkDetector()

	// Angular has 8 indicators total, so each match contributes 0.125 to confidence.
	// Note: some test bodies match multiple indicators (e.g., ng-binding triggers both
	// the ng-binding and \bng-[a-z]+= patterns).
	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		// Single-indicator matches (may overlap with the \bng-[a-z]+= pattern)
		{"ng-version", `<div ng-version="15.0.0"></div>`, 0.25},            // ng-version + \bng-[a-z]+=
		{"angular.js", `<script src="angular.js"></script>`, 0.125},       // angular(\.min)?\.js only
		{"ng- attribute", `<div [ng-app]="myApp"></div>`, 0.25},           // \[ng- + ng-app
		{"ng-binding", `<span ng-binding="name"></span>`, 0.25},            // ng-binding + \bng-[a-z]+=
		// AngularJS 1.x specific indicators
		{"ng-app directive", `<body ng-app="myApp"></body>`, 0.25},        // ng-app + \bng-[a-z]+=
		{"ng-controller", `<div ng-controller="MainCtrl"></div>`, 0.25},    // ng-controller + \bng-[a-z]+=
		{"angular.module", `<script>angular.module("app",[])</script>`, 0.125}, // angular\.module only
		// Multi-indicator combinations
		{"two legacy indicators", `<body ng-app="x"></body><div ng-controller="y"></div>`, 0.375}, // ng-app + ng-controller + \bng-[a-z]+=
		{"modern + legacy", `<div ng-version="15"></div><script src="angular.min.js"></script>`, 0.375},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "Angular" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected Angular framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectSvelte verifies Svelte detection.
func TestFrameworkDetectSvelte(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		{"svelte- class", `<div class="svelte-abc123"></div>`, 0.5},
		{"__svelte", `<script>var __svelte={}</script>`, 0.5},
		{"both indicators", `<div class="svelte-a1b2c3d4"></div><script>__svelte={}</script>`, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "Svelte" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected Svelte framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectNextJS verifies Next.js detection.
func TestFrameworkDetectNextJS(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		{"__NEXT_DATA__", `<script id="__NEXT_DATA__">{"props":{}}</script>`, 0.5},
		{"_next/static", `<script src="/_next/static/chunks/main.js"></script>`, 0.5},
		{"both", `<script id="__NEXT_DATA__">{}</script><script src="/_next/static/app.js"></script>`, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "Next.js" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected Next.js framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectNuxtJS verifies Nuxt.js detection.
func TestFrameworkDetectNuxtJS(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		{"__NUXT__", `<script>window.__NUXT__={}</script>`, 0.5},
		{"_nuxt path", `<script src="/_nuxt/app.js"></script>`, 0.5},
		{"both", `<script>__NUXT__={}</script><link href="/_nuxt/style.css">`, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "Nuxt.js" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected Nuxt.js framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectJQuery verifies jQuery detection.
func TestFrameworkDetectJQuery(t *testing.T) {
	fd := NewFrameworkDetector()

	tests := []struct {
		name     string
		body     string
		wantConf float64
	}{
		{"jquery.min.js", `<script src="jquery.min.js"></script>`, 0.5},
		{"jQuery.fn", `<script>jQuery.fn.plugin = function(){}</script>`, 0.5},
		{"both", `<script src="jquery.min.js"></script><script>jQuery.fn.x={}</script>`, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{}
			results := fd.Detect(resp, tt.body)

			var found bool
			for _, fw := range results {
				if fw.Name == "jQuery" {
					found = true
					if fw.Confidence != tt.wantConf {
						t.Errorf("Expected confidence=%f, got %f", tt.wantConf, fw.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("Expected jQuery framework, got %v", results)
			}
		})
	}
}

// TestFrameworkDetectMultiple verifies that multiple frameworks in the same
// response are all detected.
func TestFrameworkDetectMultiple(t *testing.T) {
	fd := NewFrameworkDetector()
	body := `<div id="react-root"></div><script src="vue.min.js"></script><div ng-version="14"></div>`

	resp := &http.Response{}
	results := fd.Detect(resp, body)

	gotNames := make(map[string]float64)
	for _, fw := range results {
		gotNames[fw.Name] = fw.Confidence
	}

	expected := map[string]bool{"React": true, "Vue": true, "Angular": true}
	for name := range expected {
		if _, ok := gotNames[name]; !ok {
			t.Errorf("Expected framework %s to be detected, got %v", name, gotNames)
		}
	}
	if len(results) < 3 {
		t.Errorf("Expected at least 3 frameworks, got %d: %v", len(results), results)
	}
}

// TestFrameworkDetectNone verifies that a plain HTML response yields no
// framework detections.
func TestFrameworkDetectNone(t *testing.T) {
	fd := NewFrameworkDetector()
	body := `<html><head><title>Plain Page</title></head><body><p>Hello World</p></body></html>`

	resp := &http.Response{}
	results := fd.Detect(resp, body)

	if len(results) != 0 {
		t.Errorf("Expected no frameworks detected, got %d: %v", len(results), results)
	}
}

// TestFrameworkRiskInfo verifies RiskInfo returns correct DOM XSS sinks for
// each framework, and false/nil for frameworks without known sinks.
func TestFrameworkRiskInfo(t *testing.T) {
	tests := []struct {
		name      string
		fwName    string
		wantRisk  bool
		wantSinks []string
	}{
		{"React", "React", true, []string{"dangerouslySetInnerHTML", "innerHTML"}},
		{"Vue", "Vue", true, []string{"v-html", "innerHTML"}},
		{"Angular", "Angular", true, []string{"[innerHTML]", "bypassSecurityTrustHtml"}},
		{"Svelte", "Svelte", true, []string{"@html", "innerHTML"}},
		{"Next.js (no sinks)", "Next.js", false, nil},
		{"jQuery (no sinks)", "jQuery", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &FrameworkInfo{Name: tt.fwName}
			hasRisk, sinks := fw.RiskInfo()

			if hasRisk != tt.wantRisk {
				t.Errorf("RiskInfo() risk=%v, want %v", hasRisk, tt.wantRisk)
			}
			if !equalSlices(sinks, tt.wantSinks) {
				t.Errorf("RiskInfo() sinks=%v, want %v", sinks, tt.wantSinks)
			}
		})
	}
}

// TestFrameworkConfidenceValues verifies that confidence is always in (0, 1]
// and equals matched_indicators / total_indicators.
func TestFrameworkConfidenceValues(t *testing.T) {
	fd := NewFrameworkDetector()

	// Svelte has exactly 2 indicators. Match both → confidence = 1.0.
	body := `<div class="svelte-abc123"></div><script>var __svelte={}</script>`
	resp := &http.Response{}
	results := fd.Detect(resp, body)

	for _, fw := range results {
		if fw.Confidence <= 0 || fw.Confidence > 1.0 {
			t.Errorf("Framework %s confidence=%f outside (0,1]", fw.Name, fw.Confidence)
		}
		if fw.Name == "Svelte" && fw.Confidence != 1.0 {
			t.Errorf("Expected Svelte confidence=1.0, got %f", fw.Confidence)
		}
	}
}

// equalSlices checks string slice equality (nil-safe).
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
