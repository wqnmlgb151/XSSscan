package dom

import (
	"context"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/model"
	"net/http"
	"strings"
)

// applyTargetState gives observation and replay the same authentication snapshot.
func (s *Scanner) applyTargetState(ctx context.Context, target model.Target) error {
	headers := network.Headers{}
	for key, value := range target.Headers {
		if !strings.EqualFold(key, "Proxy-Authorization") && !strings.EqualFold(key, "Content-Length") {
			headers[key] = value
		}
	}
	if len(headers) > 0 {
		if err := chromedp.Run(ctx, network.SetExtraHTTPHeaders(headers)); err != nil {
			return err
		}
	}
	cookies := target.Cookies
	if s.auth != nil {
		cookies = append(append([]*http.Cookie(nil), s.auth.Cookies...), cookies...)
	}
	var params []*network.CookieParam
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		params = append(params, &network.CookieParam{Name: cookie.Name, Value: cookie.Value, URL: target.URL, Domain: cookie.Domain, Path: path, HTTPOnly: cookie.HttpOnly, Secure: cookie.Secure})
	}
	if len(params) > 0 {
		return chromedp.Run(ctx, network.SetCookies(params))
	}
	return nil
}
