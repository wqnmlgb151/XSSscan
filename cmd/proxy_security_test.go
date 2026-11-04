package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestProxyStatusNeverPrintsPassword(t *testing.T) {
	defer saveCfg()()
	cfg.Silent = false
	_, diagnostics, err := captureCLIStreams(t, func() error {
		logProxyEndpoint("http://proxy-user:proxy-password-canary@127.0.0.1:8888")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diagnostics, "127.0.0.1:8888") || strings.Contains(diagnostics, "proxy-password-canary") || strings.Contains(diagnostics, base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-password-canary"))) {
		t.Fatal("proxy log contains credentials or lost endpoint")
	}
}
