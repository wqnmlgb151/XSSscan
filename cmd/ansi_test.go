package main

import (
	"strings"
	"testing"
)

func TestStripANSI_CSISequence(t *testing.T) {
	in := "\x1b[31mred\x1b[0m"
	if got := stripANSI(in); got != "red" {
		t.Errorf("stripANSI(%q) = %q, want %q", in, got, "red")
	}
}

func TestStripANSI_OSCSequence(t *testing.T) {
	in := "\x1b]0;window title\x07payload"
	if got := stripANSI(in); got != "payload" {
		t.Errorf("stripANSI(%q) = %q, want %q", in, got, "payload")
	}
}

func TestStripANSI_MultiParamCSI(t *testing.T) {
	in := "\x1b[1;2;38;5;196mstyled"
	if got := stripANSI(in); got != "styled" {
		t.Errorf("stripANSI(%q) = %q, want %q", in, got, "styled")
	}
}

func TestStripANSI_BareESC(t *testing.T) {
	in := "a\x1bb"
	if got := stripANSI(in); got != "ab" {
		t.Errorf("stripANSI(%q) = %q, want %q", in, got, "ab")
	}
}

func TestStripANSI_PlainText(t *testing.T) {
	inputs := []string{
		"normal text",
		"中文内容",
		"emoji 🎯 mixed",
		"<script>alert(1)</script>", // HTML must NOT be stripped
	}
	for _, in := range inputs {
		if got := stripANSI(in); got != in {
			t.Errorf("stripANSI(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestStripANSI_Mixed(t *testing.T) {
	in := "\x1b[32m成功\x1b[0m \x1b]0;title\x07done"
	got := stripANSI(in)
	if got != "成功 done" {
		t.Errorf("stripANSI() = %q, want %q", got, "成功 done")
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("stripANSI() result still contains escape character: %q", got)
	}
}
