package browser

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBrowserProxyConfigurationKeepsCredentialsOutOfArguments(t *testing.T) {
	proxy, err := ParseProxy("http://user:proxy%40canary@127.0.0.1:8080", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Server() != "http://127.0.0.1:8080" || proxy.Username() != "user" || proxy.Password() != "proxy@canary" {
		t.Fatal("proxy configuration changed")
	}
	data, err := json.Marshal(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %s", proxy, proxy, data), "canary") {
		t.Fatal("proxy credentials entered display output")
	}
	if _, err := ParseProxy("socks5://user:secret@127.0.0.1:8080", "", "", false); err == nil {
		t.Fatal("unsupported SOCKS authentication silently accepted")
	}
}
