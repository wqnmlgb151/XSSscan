package analyze

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestSecureMarkerReaderAndPrefixValidation(t *testing.T) {
	value, err := randomMarkerText(bytes.NewReader(make([]byte, MarkerRandomLen)), "abcdefghijklmnopqrstuvwxyz0123456789", MarkerRandomLen)
	if err != nil || value != strings.Repeat("a", MarkerRandomLen) {
		t.Fatalf("reader contract %q %v", value, err)
	}
	if _, err := randomMarkerText(bytes.NewReader(nil), "abc", 1); err != io.EOF {
		t.Fatalf("entropy failure must propagate: %v", err)
	}
	for _, prefix := range []string{"0bad", "UPPER", "a-b", strings.Repeat("a", 33), "a'"} {
		if ValidateMarkerPrefix(prefix) == nil {
			t.Errorf("invalid prefix accepted %q", prefix)
		}
	}
	ctx, err := WithMarkerPrefix(context.Background(), "customprefix")
	if err != nil {
		t.Fatal(err)
	}
	marker := GenerateMarkerContext(ctx)
	if !strings.HasPrefix(marker, "customprefix") || len(marker) != len("customprefix")+MarkerRandomLen {
		t.Fatal("context prefix ignored")
	}
	random, err := RandomMarkerPrefix()
	if err != nil || ValidateMarkerPrefix(random) != nil || len(random) != 10 {
		t.Fatal("random prefix shape")
	}
	if DetectFilterProfile("customprefix<>\"'", "customprefix") == nil {
		t.Fatal("custom filter profile prefix ignored")
	}
}
