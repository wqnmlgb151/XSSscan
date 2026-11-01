package jsanalysis

import (
	"fmt"
	"strings"
	"testing"
)

func TestSourceSinkDataFlow(t *testing.T) {
	for _, tc := range []struct{ source, kind, key, sink string }{
		{`const p=new URLSearchParams(location.search); const x=p.get('view'); const alias=decodeURIComponent(x); document.body.innerHTML='<b>'+alias+'</b>';`, "query", "view", "innerHTML"},
		{`const x=new URLSearchParams(location.hash.slice(1)).get('route');document.body.outerHTML=x;`, "fragment", "route", "outerHTML"},
		{`const saved=localStorage.getItem('template'); const value=saved; document.write(value);`, "localStorage", "template", "document.write"},
		{"const x=sessionStorage.getItem('draft'); el.innerHTML=`<p>${x}</p>`;", "sessionStorage", "draft", "innerHTML"},
		{`function render(value){document.body.innerHTML=value} const q=new URLSearchParams(location.search).get('hidden'); render(q);`, "query", "hidden", "innerHTML"},
		{`const render=(value)=>el.insertAdjacentHTML('beforeend',value);render(localStorage.getItem('view'));`, "localStorage", "view", "insertAdjacentHTML"},
		{`addEventListener('DOMContentLoaded',()=>{const v=new URLSearchParams(location.search).get('q'); el.innerHTML=v;});`, "query", "q", "innerHTML"},
		{`let value='';if(flag){value=new URLSearchParams(location.search).get('q')}else{value='safe'} el.innerHTML=value;`, "query", "q", "innerHTML"},
		{`const render=x=>el.innerHTML=x;if(flag){}render(localStorage.getItem('template'));`, "localStorage", "template", "innerHTML"},
		{`let q='';function fill(){q=localStorage.getItem('template')}if(flag){fill()}el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`let q='';flag?(q=localStorage.getItem('template')):(q='safe');el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`{var q=localStorage.getItem('template')}el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`let q=localStorage.getItem('template');flag&&(q='safe');el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`let q=localStorage.getItem('template');flag||(q='safe');el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`let q=localStorage.getItem('template');flag??(q='safe');el.innerHTML=q;`, "localStorage", "template", "innerHTML"},
		{`el.setAttribute('ONERROR',localStorage.getItem('template'));`, "localStorage", "template", "setAttribute(onerror)"},
	} {
		a := Parse(tc.source, false)
		if a.Error != "" || a.FlowError != "" {
			t.Fatalf("source=%s error=%s flow=%s", tc.source, a.Error, a.FlowError)
		}
		found := false
		for _, f := range a.Flows {
			if f.Source.Kind == tc.kind && f.Source.Key == tc.key && f.Sink == tc.sink {
				found = true
				if f.Source.Start < 0 || f.Source.End > len(tc.source) || f.Start < 0 || f.End > len(tc.source) {
					t.Fatal(f)
				}
			}
		}
		if !found {
			t.Errorf("missing %s/%s -> %s: %+v", tc.kind, tc.key, tc.sink, a.Flows)
		}
	}
}

func TestHandlerDataFlowUsesOriginalOffsets(t *testing.T) {
	source := `return el.innerHTML=localStorage.getItem('template')`
	a := Parse(source, true)
	if a.Error != "" || a.FlowError != "" || len(a.Flows) != 1 || source[a.Flows[0].Source.Start:a.Flows[0].Source.End] != `localStorage.getItem('template')` {
		t.Fatalf("handler=%+v", a)
	}
}

func TestModuleDataFlow(t *testing.T) {
	a := ParseWithMode(`export const p=new URLSearchParams(location.search); export function render(v){el.innerHTML=v} render(p.get('view'));`, ModuleMode)
	if a.Error != "" || a.FlowError != "" || len(a.Flows) != 1 || a.Flows[0].Source.Key != "view" {
		t.Fatal(a)
	}
}

func TestDataFlowBranchCopiesShareWorkBudget(t *testing.T) {
	source := ""
	for i := 0; i < 500; i++ {
		source += fmt.Sprintf("let v%d=0;", i)
	}
	source += strings.Repeat("if(flag){}", 100)
	a := Parse(source, false)
	if a.Error != "" || a.FlowError == "" {
		t.Fatalf("copy budget not applied: syntax=%s flow=%s", a.Error, a.FlowError)
	}
}

func TestAlternativeClosureCaptureIsUnknown(t *testing.T) {
	a := Parse(`function make(v){return ()=>v}const f=flag?make(localStorage.getItem('a')):make(localStorage.getItem('b'));el.innerHTML=f();`, false)
	if a.Error != "" || a.FlowError == "" {
		t.Fatalf("different captures silently merged: %+v", a)
	}
}

func TestDataFlowDoesNotInventSourceOrSink(t *testing.T) {
	for _, source := range []string{
		`const q=location.hash;el.textContent=q;`,
		`const q="location.hash";el.innerHTML=q;`,
		`const location={hash:'safe'}; el.innerHTML=location.hash;`,
		`const localStorage={getItem:()=>"safe"};el.innerHTML=localStorage.getItem('q');`,
		`const x=location.hash;{const x='safe';el.innerHTML=x}`,
		`let q=location.hash;q='safe';el.innerHTML=q;`,
		`if(false){el.innerHTML=location.hash;}`,
		`false && document.write(location.hash);`,
		`const render=(q)=>{q='safe';el.innerHTML=q;};render(location.hash);`,
	} {
		a := Parse(source, false)
		if a.Error != "" || a.FlowError != "" || len(a.Flows) != 0 {
			t.Errorf("unexpected flow source=%s analysis=%+v", source, a)
		}
	}
}

func TestDataFlowCacheIsolationAndBudget(t *testing.T) {
	source := `el.innerHTML=localStorage.getItem('template');`
	a := Parse(source, false)
	if len(a.Flows) != 1 {
		t.Fatal(a)
	}
	a.Flows[0].Source.Key = "changed"
	if b := Parse(source, false); b.Flows[0].Source.Key != "template" {
		t.Fatal("flow cache mutated")
	}
	if a := Parse(strings.Repeat(`el.innerHTML=location.hash;`, 70), false); a.Error != "" || a.FlowError == "" || len(a.Flows) > 64 {
		t.Fatalf("unbounded/inaccurate flow limit: %+v", a)
	}
}
