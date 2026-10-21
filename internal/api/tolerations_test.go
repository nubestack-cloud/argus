package api

import "testing"

// splitObjectKey underpins the tolerations table's Kind/namespace/name columns,
// which exist because the composite key's most identifying part — the object
// NAME — is at the end, so a width-limited column truncates away exactly the
// half a reader needs (BUGS.md item 32).
func TestSplitObjectKey(t *testing.T) {
	gvk, ns, name := splitObjectKey("apps/v1/Deployment|argus-e2e|web")
	if gvk != "apps/v1/Deployment" || ns != "argus-e2e" || name != "web" {
		t.Errorf("got (%q, %q, %q)", gvk, ns, name)
	}

	// A cluster-scoped object legitimately has no namespace. Normal, not a
	// parse failure — Node and PersistentVolume tolerations are real.
	gvk, ns, name = splitObjectKey("v1/Node||worker-0")
	if gvk != "v1/Node" || ns != "" || name != "worker-0" {
		t.Errorf("cluster-scoped: got (%q, %q, %q)", gvk, ns, name)
	}

	// Anything unexpected falls back to "all of it is the name". Showing the
	// whole key is merely verbose; showing the wrong part as the name would
	// mislead, which is the failure worth avoiding.
	for _, weird := range []string{"", "just-a-name", "a|b", "a|b|c|d"} {
		g, n, nm := splitObjectKey(weird)
		if g != "" || n != "" || nm != weird {
			t.Errorf("splitObjectKey(%q) = (%q, %q, %q), want the whole string as the name", weird, g, n, nm)
		}
	}
}
