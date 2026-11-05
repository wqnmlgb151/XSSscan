package execverify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
)

var dialogCall = regexp.MustCompile(`\b(alert|confirm|prompt)\(\s*(?:1|'[^'\r\n]*'|"[^"\r\n]*")\s*\)`)
var dialogTag = regexp.MustCompile("\\b(alert|confirm|prompt)`[^`\\\\$\\r\\n]*`")

func SupportsDialogVerification(value string) bool {
	return dialogCall.MatchString(value) || dialogTag.MatchString(value)
}

// InstrumentDialogPayload gives supported dialog calls a unique candidate token.
// Numeric character codes preserve HTML attribute quote compatibility.
func InstrumentDialogPayload(value string) (string, string, error) {
	if !SupportsDialogVerification(value) {
		return "", "", fmt.Errorf("payload has no supported dialog call for candidate-specific verification")
	}
	token := analyze.GenerateMarker()
	codes := make([]string, 0, len(token))
	for _, r := range token {
		codes = append(codes, strconv.Itoa(int(r)))
	}
	expression := "String.fromCharCode(" + strings.Join(codes, ",") + ")"
	instrumented := dialogCall.ReplaceAllStringFunc(value, func(call string) string {
		name := call[:strings.Index(call, "(")]
		return name + "(" + expression + ")/*" + token + "*/"
	})
	// Keep the tagged-template form; introducing parentheses would invalidate
	// the very no-parentheses filter bypass under verification.
	instrumented = dialogTag.ReplaceAllStringFunc(instrumented, func(call string) string { name := call[:strings.Index(call, "`")]; return name + "`" + token + "`" })
	return instrumented, token, nil
}
