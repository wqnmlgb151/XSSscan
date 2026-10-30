package dom

import (
	"net/url"
	"sort"
)

func sortedQueryKeys(u *url.URL) []string {
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
