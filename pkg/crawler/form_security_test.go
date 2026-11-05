package crawler

import "testing"

func TestFormDefaultsPreserveSuccessfulControls(t *testing.T) {
	forms, err := extractForms(`<form action="/save" method="post"><input name="message" value="original"><input type="hidden" name="csrf" value="synthetic-csrf"><select name="choice"><option value="a">A</option><option value="b" selected>B</option></select><input type="checkbox" name="checked" value="yes" checked><input type="checkbox" name="unchecked" value="no"><input type="radio" name="radio" value="r" checked></form>`, "http://127.0.0.1/")
	if err != nil || len(forms) != 1 {
		t.Fatalf("extract: %v", err)
	}
	values := forms[0].DefaultValues()
	for name, expected := range map[string]string{"message": "test", "csrf": "synthetic-csrf", "choice": "b", "checked": "yes", "radio": "r"} {
		if values.Get(name) != expected {
			t.Fatalf("%s default changed", name)
		}
	}
	if values.Has("unchecked") {
		t.Fatal("unchecked checkbox submitted")
	}
	if len(forms[0].Fields) != 6 || len(forms[0].Fields[2].Options) != 2 {
		t.Fatal("input metadata lost")
	}
}

func TestURLScopeRejectsUnsafeAndExcludedPaths(t *testing.T) {
	scope, err := NewURLScope([]string{`/excluded`}, []string{`^http://127\.0\.0\.1/`})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"logout", "signout", "delete", "remove", "destroy", "unsubscribe", "password", "passwd", "payment", "checkout", "order", "transfer", "excluded"} {
		if scope.Check("http://127.0.0.1/"+path) == nil {
			t.Fatalf("unsafe path allowed: %s", path)
		}
	}
	if scope.Check("http://127.0.0.1/included") != nil {
		t.Fatal("allowed URL blocked")
	}
	if scope.Check("http://localhost/included") == nil {
		t.Fatal("include scope ignored")
	}
}

func TestFormDefaultsKeepExplicitEmptyAndDisabledSelection(t *testing.T) {
	forms, err := extractForms(`<form><input type="checkbox" name="empty" value="" checked><select name="disabled"><option value="a">A</option><option value="b" selected disabled>B</option></select></form>`, "http://127.0.0.1/")
	if err != nil || len(forms) != 1 {
		t.Fatal(err)
	}
	values := forms[0].DefaultValues()
	if !values.Has("empty") || values.Get("empty") != "" {
		t.Fatal("explicit empty checkbox replaced")
	}
	if values.Has("disabled") {
		t.Fatal("disabled selected option replaced by another option")
	}
}
