package ssrfguard

import (
	"net"
	"testing"
)

func TestReservedAndEmbeddedAddressesAreRejected(t *testing.T) {
	for _, literal := range []string{
		"224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		"198.18.0.1", "198.19.255.255", "192.0.0.8", "192.0.2.1", "198.51.100.1", "203.0.113.1",
		"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"100:0:0:1::1", "3fff::1", "5f00::1", "fec0::1", "ff02::1", "::ffff:127.0.0.1",
	} {
		if err := (Policy{AllowPrivate: false}).CheckIP(net.ParseIP(literal)); err == nil {
			t.Errorf("restricted literal accepted: %s", literal)
		}
	}
}
