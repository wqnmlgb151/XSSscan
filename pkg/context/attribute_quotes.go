package context

import "strings"

type attributeDelimiter struct{ name, quote string }

// attributeDelimiters supplements the HTML tokenizer with raw quote metadata.
// It does not decode entities. Consumers accept metadata only when the raw name
// agrees with the tokenizer's attribute at the same index; ambiguity stays unknown.
func attributeDelimiters(tag string) []attributeDelimiter {
	space := func(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' }
	i := 1 // skip '<'; callers supply a tokenizer start/self-closing tag
	for i < len(tag) && !space(tag[i]) && tag[i] != '/' && tag[i] != '>' {
		i++
	}
	var result []attributeDelimiter
	for i < len(tag) {
		for i < len(tag) && (space(tag[i]) || tag[i] == '/') {
			i++
		}
		if i == len(tag) || tag[i] == '>' {
			break
		}
		start := i
		// HTML permits a leading '=' in an attribute name as a parse error.
		i++
		for i < len(tag) && !space(tag[i]) && tag[i] != '/' && tag[i] != '>' && tag[i] != '=' {
			i++
		}
		name := strings.ToLower(tag[start:i])
		for i < len(tag) && space(tag[i]) {
			i++
		}
		quote := ""
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && space(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '\'' || tag[i] == '"') {
				q := tag[i]
				quote = string(q)
				i++
				for i < len(tag) && tag[i] != q {
					i++
				}
				if i == len(tag) {
					return nil
				}
				i++
			} else {
				for i < len(tag) && !space(tag[i]) && tag[i] != '>' {
					i++
				}
			}
		}
		result = append(result, attributeDelimiter{name, quote})
	}
	return result
}
