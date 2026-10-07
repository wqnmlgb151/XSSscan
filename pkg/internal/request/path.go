package request

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// InjectPathValue uses analyzer segment indexes or named framework placeholders.
// Untouched escaped segments remain intact, including encoded slashes.
func InjectPathValue(rawURL, name, original, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	segments := strings.Split(u.EscapedPath(), "/")
	index := -1
	if strings.HasPrefix(name, "path[") && strings.HasSuffix(name, "]") {
		index, err = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "path["), "]"))
		if err != nil || index < 1 || index >= len(segments) || segments[index] == "" {
			return "", fmt.Errorf("invalid path parameter %q", name)
		}
	} else {
		for i, segment := range segments {
			decoded, err := url.PathUnescape(segment)
			if err != nil {
				return "", err
			}
			if decoded == "{"+name+"}" || decoded == ":"+name || decoded == "<"+name+">" || decoded == "["+name+"]" || (original != "" && decoded == original) {
				index = i
				break
			}
		}
	}
	if index < 1 {
		return "", fmt.Errorf("path parameter %q not found", name)
	}
	segments[index] = url.PathEscape(value)
	u.RawPath = strings.Join(segments, "/")
	u.Path, err = url.PathUnescape(u.RawPath)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
