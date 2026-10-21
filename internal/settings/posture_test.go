package settings

import (
	"encoding/json"
	"testing"
)

func TestPostureExcludes(t *testing.T) {
	c := Config{PostureDisabledChecks: []string{"runAsRoot"}, PostureIgnoredNamespaces: []string{"team-*", "*-sandbox", "legacy"}}
	for _, tc := range []struct {
		ns, check string
		want      bool
	}{
		{"prod", "RunAsRoot", true}, // check IDs match case-insensitively
		{"team-a", "noLimits", true},
		{"x-sandbox", "noLimits", true},
		{"legacy", "noLimits", true},
		{"legacy-2", "noLimits", false},
		{"prod", "noLimits", false},
		{"", "noLimits", false}, // a cluster-scoped finding is not in any namespace
	} {
		if got := c.PostureExcludes(tc.ns, tc.check); got != tc.want {
			t.Errorf("PostureExcludes(%q, %q) = %v, want %v", tc.ns, tc.check, got, tc.want)
		}
	}

	var args map[string]any
	if err := json.Unmarshal(c.WithPostureArgs(json.RawMessage(`{"category":"Security"}`)), &args); err != nil {
		t.Fatal(err)
	}
	if args["category"] != "Security" || len(args["disabledChecks"].([]any)) != 1 {
		t.Fatalf("merged args = %v, want the caller's arguments kept and the settings added", args)
	}
	if got := (Config{}).WithPostureArgs(json.RawMessage(`{}`)); string(got) != `{}` {
		t.Fatalf("no settings must leave the arguments untouched, got %s", got)
	}
}
