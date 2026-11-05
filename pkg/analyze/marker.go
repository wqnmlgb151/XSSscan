package analyze

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

const MarkerPrefix = "xsscan"
const MarkerRandomLen = 12

type markerPrefixKey struct{}

func ValidateMarkerPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if len(prefix) > 32 || prefix[0] < 'a' || prefix[0] > 'z' {
		return fmt.Errorf("marker prefix must start with a lowercase letter and contain at most 32 lowercase letters/digits")
	}
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return fmt.Errorf("marker prefix must contain only lowercase letters/digits")
		}
	}
	return nil
}

func WithMarkerPrefix(ctx context.Context, prefix string) (context.Context, error) {
	if err := ValidateMarkerPrefix(prefix); err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = MarkerPrefix
	}
	return context.WithValue(ctx, markerPrefixKey{}, prefix), nil
}

func MarkerPrefixFromContext(ctx context.Context) string {
	if ctx != nil {
		if prefix, ok := ctx.Value(markerPrefixKey{}).(string); ok {
			return prefix
		}
	}
	return MarkerPrefix
}

func randomMarkerText(reader io.Reader, alphabet string, length int) (string, error) {
	result := make([]byte, length)
	bound := big.NewInt(int64(len(alphabet)))
	for i := range result {
		n, err := rand.Int(reader, bound)
		if err != nil {
			return "", err
		}
		result[i] = alphabet[n.Int64()]
	}
	return string(result), nil
}

// GenerateMarker preserves the original SDK signature and default prefix.
func GenerateMarker() string { return GenerateMarkerContext(context.Background()) }

// GenerateMarkerContext uses the run's prefix. Entropy failures fail closed;
// no pseudorandom fallback is permitted.
func GenerateMarkerContext(ctx context.Context) string {
	prefix := MarkerPrefixFromContext(ctx)
	suffix, err := randomMarkerText(rand.Reader, "abcdefghijklmnopqrstuvwxyz0123456789", MarkerRandomLen)
	if err != nil {
		panic("cannot generate secure marker: " + err.Error())
	}
	return prefix + suffix
}

func RandomMarkerPrefix() (string, error) {
	return randomMarkerText(rand.Reader, "abcdefghijklmnopqrstuvwxyz", 10)
}
