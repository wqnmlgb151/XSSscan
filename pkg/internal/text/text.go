// Package text provides shared string utilities for the xsscan project.
package text

import "strings"

// Snippet extracts ±radius chars around the first occurrence of target in s.
// Returns a window of context for display in reports and logs.
func Snippet(s, target string, radius int) string {
	idx := strings.Index(s, target)
	if idx < 0 {
		if len(s) > radius*2 {
			return s[:radius*2] + "..."
		}
		return s
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(target) + radius
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// ContainsCI reports whether substr occurs in s, case-insensitively.
func ContainsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Truncate returns s truncated to maxLen characters with "..." appended
// if truncation occurred.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// EscapeMarkdown escapes characters that have special meaning in Markdown.
func EscapeMarkdown(s string) string {
	return markdownEscaper.Replace(s)
}

var markdownEscaper = strings.NewReplacer(
	"`", "&#96;",
	"|", "&#124;",
	"*", "&#42;",
	"_", "&#95;",
	"[", "&#91;",
	"]", "&#93;",
)
