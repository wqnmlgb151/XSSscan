package model

import "net/http"

type Target struct {
	URL     string            `json:"url" yaml:"url"`
	Method  string            `json:"method" yaml:"method"`
	Headers map[string]string `json:"headers" yaml:"headers"`
	Body    string            `json:"body" yaml:"body"`
	Cookies []*http.Cookie    `json:"-" yaml:"-"`
}

func (t *Target) HTTPMethod() string {
	if t.Method == "" {
		return http.MethodGet
	}
	return t.Method
}
