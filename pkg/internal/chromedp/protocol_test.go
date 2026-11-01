package chromedp

import (
	"testing"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

// These events exercise protocol changes observed with current Chrome. A
// successful navigation alone does not prove its accompanying events decoded.
func TestCurrentChromeProtocolEvents(t *testing.T) {
	tests := []struct {
		name, method, params string
	}{
		{"cookie partition object", "Network.responseReceivedExtraInfo", `{"requestId":"1","blockedCookies":[],"headers":{},"resourceIPAddressSpace":"Local","statusCode":200,"cookiePartitionKey":{"topLevelSite":"http://localhost","hasCrossSiteAncestor":false},"cookiePartitionKeyOpaque":false}`},
		{"loopback address space", "Network.responseReceivedExtraInfo", `{"requestId":"1","blockedCookies":[],"headers":{},"resourceIPAddressSpace":"Loopback","statusCode":200}`},
		{"initial frame navigation", "Page.frameRequestedNavigation", `{"frameId":"1","reason":"initialFrameNavigation","url":"http://localhost/","disposition":"currentTab"}`},
		{"insecure local network", "Network.loadingFailed", `{"requestId":"1","timestamp":1,"type":"Fetch","errorText":"net::ERR_FAILED","corsErrorStatus":{"corsError":"InsecureLocalNetwork","failedParameter":""}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := cdproto.UnmarshalMessage(&cdproto.Message{Method: cdproto.MethodType(tt.method), Params: []byte(tt.params)})
			if err != nil {
				t.Fatalf("decode %s: %v", tt.method, err)
			}
			if event == nil {
				t.Fatal("event decoded to nil")
			}
			switch decoded := event.(type) {
			case *network.EventResponseReceivedExtraInfo:
				if tt.name == "loopback address space" {
					if string(decoded.ResourceIPAddressSpace) != "Loopback" {
						t.Fatalf("lost address space: %v", decoded.ResourceIPAddressSpace)
					}
					return
				}
				if decoded.CookiePartitionKey == nil || decoded.CookiePartitionKey.TopLevelSite != "http://localhost" || decoded.CookiePartitionKey.HasCrossSiteAncestor {
					t.Fatalf("lost cookie partition fields: %+v", decoded.CookiePartitionKey)
				}
			case *page.EventFrameRequestedNavigation:
				if decoded.Reason != page.ClientNavigationReasonInitialFrameNavigation || decoded.URL != "http://localhost/" {
					t.Fatalf("lost navigation fields: %+v", decoded)
				}
			case *network.EventLoadingFailed:
				if decoded.CorsErrorStatus == nil || string(decoded.CorsErrorStatus.CorsError) != "InsecureLocalNetwork" {
					t.Fatalf("lost CORS failure: %+v", decoded.CorsErrorStatus)
				}
			default:
				t.Fatalf("unexpected decoded event type %T", event)
			}
		})
	}
}
