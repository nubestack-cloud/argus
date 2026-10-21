package scm

import "testing"

// BACKLOG.md F19 mechanism 1: an operator-declared mapping from a Helm
// release (or a label selector) to a repository + path, stored in
// repository_bindings.spec.objectMappings and matched hub-side when
// get_gitops_ownership itself finds no repo. These tests cover the parsing
// (bindingSpec/applySpec, alongside TestApplySpec's existing coverage of the
// rest of that shape) and the two pure matching predicates, MatchesRelease
// and MatchesLabels — the DB-backed lookup itself (FindObjectMapping) is
// covered by objectmapping_db_test.go, which also proves RLS isolation.

func TestApplySpec_ObjectMappings(t *testing.T) {
	t.Run("release-name form", func(t *testing.T) {
		raw := []byte(`{"objectMappings":[{"releaseName":"payments","namespace":"prod","path":"envs/prod/payments"}]}`)
		var b Binding
		if err := applySpec(&b, raw); err != nil {
			t.Fatal(err)
		}
		if len(b.ObjectMappings) != 1 {
			t.Fatalf("ObjectMappings = %+v, want exactly 1", b.ObjectMappings)
		}
		m := b.ObjectMappings[0]
		if m.ReleaseName != "payments" || m.Namespace != "prod" || m.Path != "envs/prod/payments" {
			t.Errorf("decoded mapping = %+v", m)
		}
		if len(m.LabelSelector) != 0 {
			t.Errorf("LabelSelector = %+v, want none for the release-name form", m.LabelSelector)
		}
	})

	t.Run("label-selector form", func(t *testing.T) {
		raw := []byte(`{"objectMappings":[{"labelSelector":{"team":"payments","tier":"backend"},"path":"envs/prod/shared"}]}`)
		var b Binding
		if err := applySpec(&b, raw); err != nil {
			t.Fatal(err)
		}
		if len(b.ObjectMappings) != 1 {
			t.Fatalf("ObjectMappings = %+v, want exactly 1", b.ObjectMappings)
		}
		m := b.ObjectMappings[0]
		if m.ReleaseName != "" || m.Namespace != "" {
			t.Errorf("release fields set on a label-selector mapping: %+v", m)
		}
		if m.LabelSelector["team"] != "payments" || m.LabelSelector["tier"] != "backend" || m.Path != "envs/prod/shared" {
			t.Errorf("decoded mapping = %+v", m)
		}
	})

	t.Run("several mappings on one binding", func(t *testing.T) {
		raw := []byte(`{"objectMappings":[
			{"releaseName":"payments","namespace":"prod","path":"envs/prod/payments"},
			{"labelSelector":{"team":"checkout"},"path":"envs/prod/checkout"}
		]}`)
		var b Binding
		if err := applySpec(&b, raw); err != nil {
			t.Fatal(err)
		}
		if len(b.ObjectMappings) != 2 {
			t.Fatalf("ObjectMappings = %+v, want exactly 2", b.ObjectMappings)
		}
	})

	t.Run("no objectMappings key at all", func(t *testing.T) {
		// A binding registered before F19, or with none configured — must
		// decode to an empty/nil list, not an error, and must not disturb
		// the rest of the spec (see TestApplySpec's "what SaveBinding
		// writes" case for that half).
		var b Binding
		if err := applySpec(&b, []byte(`{"pullRequest":{"enabled":true}}`)); err != nil {
			t.Fatal(err)
		}
		if len(b.ObjectMappings) != 0 {
			t.Errorf("ObjectMappings = %+v, want none", b.ObjectMappings)
		}
	})

	t.Run("a spec that does not parse degrades to no mappings, same as no pull requests", func(t *testing.T) {
		// TestApplySpec already covers PullRequestEnabled going false for
		// this case; ObjectMappings must degrade the same honest way rather
		// than panicking or retaining a stale value.
		var b Binding
		if err := applySpec(&b, []byte(`{not json`)); err == nil {
			t.Fatal("an unreadable spec was accepted")
		}
		if len(b.ObjectMappings) != 0 {
			t.Errorf("ObjectMappings = %+v, want none when the spec cannot be read", b.ObjectMappings)
		}
	})
}

func TestObjectMapping_Validate(t *testing.T) {
	cases := []struct {
		name    string
		mapping ObjectMapping
		wantErr bool
	}{
		{
			name:    "valid release form",
			mapping: ObjectMapping{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"},
			wantErr: false,
		},
		{
			name:    "valid label-selector form",
			mapping: ObjectMapping{LabelSelector: map[string]string{"team": "payments"}, Path: "envs/prod/payments"},
			wantErr: false,
		},
		{
			name:    "missing path",
			mapping: ObjectMapping{ReleaseName: "payments", Namespace: "prod"},
			wantErr: true,
		},
		{
			name:    "blank path",
			mapping: ObjectMapping{ReleaseName: "payments", Namespace: "prod", Path: "   "},
			wantErr: true,
		},
		{
			name:    "neither form supplied",
			mapping: ObjectMapping{Path: "envs/prod/payments"},
			wantErr: true,
		},
		{
			name:    "both forms supplied — ambiguous",
			mapping: ObjectMapping{ReleaseName: "payments", Namespace: "prod", LabelSelector: map[string]string{"team": "payments"}, Path: "envs/prod/payments"},
			wantErr: true,
		},
		{
			name:    "releaseName without namespace",
			mapping: ObjectMapping{ReleaseName: "payments", Path: "envs/prod/payments"},
			wantErr: true,
		},
		{
			name:    "namespace without releaseName",
			mapping: ObjectMapping{Namespace: "prod", Path: "envs/prod/payments"},
			wantErr: true,
		},
		{
			name:    "empty labelSelector map counts as no selector",
			mapping: ObjectMapping{LabelSelector: map[string]string{}, Path: "envs/prod/payments"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mapping.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want an error for %+v", tc.mapping)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil for %+v", err, tc.mapping)
			}
		})
	}
}

func TestObjectMapping_MatchesRelease(t *testing.T) {
	m := ObjectMapping{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"}

	cases := []struct {
		name            string
		releaseName, ns string
		want            bool
	}{
		{"exact match", "payments", "prod", true},
		{"wrong namespace", "payments", "staging", false},
		{"wrong release name", "checkout", "prod", false},
		{"empty release name from caller", "", "prod", false},
		{"empty namespace from caller", "payments", "", false},
		{"both empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.MatchesRelease(tc.releaseName, tc.ns); got != tc.want {
				t.Errorf("MatchesRelease(%q, %q) = %v, want %v", tc.releaseName, tc.ns, got, tc.want)
			}
		})
	}

	label := ObjectMapping{LabelSelector: map[string]string{"team": "payments"}, Path: "envs/prod/payments"}
	if label.MatchesRelease("payments", "prod") {
		t.Error("a label-selector-form mapping matched a release — the two forms must stay mutually exclusive")
	}
}

func TestObjectMapping_MatchesLabels(t *testing.T) {
	m := ObjectMapping{LabelSelector: map[string]string{"team": "payments", "tier": "backend"}, Path: "envs/prod/payments"}

	cases := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"exact match", map[string]string{"team": "payments", "tier": "backend"}, true},
		{"subset match — object carries extra labels", map[string]string{"team": "payments", "tier": "backend", "app": "checkout"}, true},
		{"missing one required key", map[string]string{"team": "payments"}, false},
		{"one value differs", map[string]string{"team": "payments", "tier": "frontend"}, false},
		{"no labels at all", nil, false},
		{"disjoint labels", map[string]string{"unrelated": "value"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.MatchesLabels(tc.labels); got != tc.want {
				t.Errorf("MatchesLabels(%v) = %v, want %v", tc.labels, got, tc.want)
			}
		})
	}

	release := ObjectMapping{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"}
	if release.MatchesLabels(map[string]string{"team": "payments"}) {
		t.Error("a release-form mapping (empty LabelSelector) matched labels — it must never match")
	}
}
