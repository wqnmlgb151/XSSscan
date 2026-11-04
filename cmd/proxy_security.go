package main

import "net/url"

func logProxyEndpoint(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	statusCyan("[*] Using proxy: %s://%s\n", u.Scheme, u.Host)
}
