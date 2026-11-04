package crawler

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"net/url"
	"regexp"
)

var unsafeActionPath = regexp.MustCompile(`(?i)(logout|signout|delete|remove|destroy|unsubscribe|password|passwd|payment|checkout|order|transfer)`)

// URLScope applies to discovery links and form actions, before they are fetched.
type URLScope struct{ exclude, include []*regexp.Regexp }

func NewURLScope(exclude, include []string) (*URLScope, error) {
	s := &URLScope{}
	for index, patterns := range [][]string{exclude, include} {
		for _, pattern := range patterns {
			r, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid URL scope regex: %w", err)
			}
			if index == 0 {
				s.exclude = append(s.exclude, r)
			} else {
				s.include = append(s.include, r)
			}
		}
	}
	return s, nil
}

func (s *URLScope) Check(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid discovery URL")
	}
	if unsafeActionPath.MatchString(u.Path) {
		return fmt.Errorf("unsafe action path skipped")
	}
	return s.CheckConfigured(raw)
}

func (s *URLScope) CheckConfigured(raw string) error {
	if s == nil {
		return nil
	}
	for _, pattern := range s.exclude {
		if pattern.MatchString(raw) {
			return fmt.Errorf("excluded by --exclude-url")
		}
	}
	if len(s.include) > 0 {
		for _, pattern := range s.include {
			if pattern.MatchString(raw) {
				return nil
			}
		}
		return fmt.Errorf("outside --include-url scope")
	}
	return nil
}

func (s *URLScope) Context(ctx context.Context) context.Context {
	return ssrfguard.WithNavigationFilter(ssrfguard.WithURLFilter(ctx, s.CheckConfigured), s.Check)
}
