// Package xsspatterns centralizes the event-handler regex family shared by
// context detection, dedup classification, and sanitization verification.
// Keeping the patterns in one place prevents drift between the four former
// independent copies (which had already diverged: verifier.go's pattern
// lacked the \b anchor, dedup.go duplicated a subset pattern).
package xsspatterns

import "regexp"

// EventHandlerAttrRe matches an exact event-handler attribute name
// (onerror, onclick, ...). Used for attribute-name classification.
var EventHandlerAttrRe = regexp.MustCompile(`(?i)^on\w+$`)

// EventHandlerAssignRe matches an event-handler assignment anywhere in a
// string (onerror=, ONLOAD =, ...). Used for payload classification and
// sanitization detection.
var EventHandlerAssignRe = regexp.MustCompile(`(?i)\bon\w+\s*=`)

// EventHandlerAssignColonRe extends EventHandlerAssignRe with colon syntax
// (onload:), used by exploit-class classification.
var EventHandlerAssignColonRe = regexp.MustCompile(`(?i)\bon\w+\s*=|\bon\w+\s*:`)
