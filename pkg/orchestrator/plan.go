// Package orchestrator coordinates detector modules without depending on CLI.
package orchestrator

import (
	"fmt"
	"strings"
	"time"
)

type Type string

const (
	Reflected Type = "reflected"
	DOM       Type = "dom"
	Stored    Type = "stored"
	Blind     Type = "blind"
)

var types = []Type{Reflected, DOM, Stored, Blind}

// Plan is immutable after construction. Empty Types means all detectors.
type Plan struct {
	Types         []Type
	ModuleTimeout time.Duration
}

// Select validates explicit type selections and exclusions before any I/O.
func Select(include, exclude string) ([]Type, error) {
	selected := make(map[Type]bool)
	if include == "" || include == "all" {
		for _, kind := range types {
			selected[kind] = true
		}
	} else {
		for _, part := range strings.Split(include, ",") {
			kind := Type(strings.TrimSpace(part))
			if !validType(kind) {
				return nil, fmt.Errorf("unknown scan type %q", part)
			}
			selected[kind] = true
		}
	}
	if exclude != "" {
		for _, part := range strings.Split(exclude, ",") {
			kind := Type(strings.TrimSpace(part))
			if !validType(kind) {
				return nil, fmt.Errorf("unknown excluded scan type %q", part)
			}
			delete(selected, kind)
		}
	}
	var result []Type
	for _, kind := range types {
		if selected[kind] {
			result = append(result, kind)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no scan types selected")
	}
	return result, nil
}

func validType(kind Type) bool {
	for _, known := range types {
		if kind == known {
			return true
		}
	}
	return false
}
