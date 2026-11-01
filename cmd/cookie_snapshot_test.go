package main

import (
	"net/http"
	"testing"
)

func TestCloneCookiesOwnsUnparsedFields(t *testing.T) {
	input := []*http.Cookie{{Name: "session", Value: "original", Unparsed: []string{"extension=original"}}, nil}
	got := cloneCookies(input)
	got[0].Unparsed[0] = "extension=other"
	if input[0].Unparsed[0] != "extension=original" || got[1] != nil {
		t.Fatal("CLI cookie snapshot shared mutable extension fields")
	}
}
