package verify

import "testing"

func TestResponseConstantBranchEvidence(t *testing.T) {
	for _, tc := range []struct {
		body string
		call bool
	}{
		{`<script>if(false){alert(1)}</script>`, false},
		{`<script type="module">true || alert(1)</script>`, false},
		{`<button onclick="false && alert(1)">x</button>`, false},
		{`<script>if(window.ready){alert(1)}</script>`, true},
		{`<script>if(false){let q='</script><svg onload=alert(1)>`, true},
	} {
		got, problem := responseJSCall(tc.body, "alert(1)")
		if got != tc.call || problem != "" {
			t.Errorf("body=%s want=%v got=%v error=%s", tc.body, tc.call, got, problem)
		}
	}
}
