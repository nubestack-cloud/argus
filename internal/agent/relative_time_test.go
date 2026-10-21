package agent

import (
	"testing"
	"time"
)

// Sign convention pinned here, once, for the whole package (relative_time.go's
// own doc comment states it in prose; these tests are the executable version):
//
//   - secondsUntil(t, now) is POSITIVE while t is still ahead of now, and
//     NEGATIVE once t has already passed — "negative-when-already-past",
//     matching a future-facing field like a renewal/expiry time. This is the
//     exact reading BUGS.md 105's investigation got backwards: a renewalTime
//     41 minutes in the future should read as a comfortably positive
//     secondsUntil, not the confidently-reported-negative "passed 30 minutes
//     ago" the model actually produced.
//   - secondsSince(t, now) is POSITIVE once t has already happened, and
//     NEGATIVE if t is, unexpectedly, still in the future — matching a
//     past-facing field like a deletionTimestamp or lastTransitionTime.
//   - Both are exactly 0 when t falls in the same second as now — the
//     boundary case BACKLOG.md C9 asks to be tested explicitly.
func TestSecondsUntil_SignConvention(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 32, 11, 0, time.UTC)

	future := now.Add(41 * time.Minute) // BUGS.md 105's own fixture shape
	if got := secondsUntil(future, now); got <= 0 {
		t.Errorf("secondsUntil(41m in the future) = %d, want a positive value (still ahead of now)", got)
	}
	if got, want := secondsUntil(future, now), int64(41*60); got != want {
		t.Errorf("secondsUntil(41m in the future) = %d, want exactly %d", got, want)
	}

	past := now.Add(-30 * time.Minute)
	if got := secondsUntil(past, now); got >= 0 {
		t.Errorf("secondsUntil(30m in the past) = %d, want a negative value (already passed)", got)
	}
	if got, want := secondsUntil(past, now), int64(-30*60); got != want {
		t.Errorf("secondsUntil(30m in the past) = %d, want exactly %d", got, want)
	}

	// Boundary: the same instant. Neither future nor past.
	if got := secondsUntil(now, now); got != 0 {
		t.Errorf("secondsUntil(now, now) = %d, want exactly 0", got)
	}
	// And still the boundary one second either side of exact equality —
	// truncation toward zero must not push either side across 0.
	if got := secondsUntil(now.Add(999*time.Millisecond), now); got != 0 {
		t.Errorf("secondsUntil(now+999ms, now) = %d, want 0 (truncates toward zero within the same second)", got)
	}
	if got := secondsUntil(now.Add(time.Second), now); got != 1 {
		t.Errorf("secondsUntil(now+1s, now) = %d, want 1", got)
	}
}

func TestSecondsSince_SignConvention(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 32, 11, 0, time.UTC)

	past := now.Add(-10 * time.Minute)
	if got := secondsSince(past, now); got <= 0 {
		t.Errorf("secondsSince(10m in the past) = %d, want a positive value (already happened)", got)
	}
	if got, want := secondsSince(past, now), int64(10*60); got != want {
		t.Errorf("secondsSince(10m in the past) = %d, want exactly %d", got, want)
	}

	future := now.Add(10 * time.Minute)
	if got := secondsSince(future, now); got >= 0 {
		t.Errorf("secondsSince(10m in the future) = %d, want a negative value (unexpectedly not yet happened)", got)
	}
	if got, want := secondsSince(future, now), int64(-10*60); got != want {
		t.Errorf("secondsSince(10m in the future) = %d, want exactly %d", got, want)
	}

	// Boundary: the same instant.
	if got := secondsSince(now, now); got != 0 {
		t.Errorf("secondsSince(now, now) = %d, want exactly 0", got)
	}
}

// TestAnnotateRelativeTimestamps_FutureFacingField is the BUGS.md 105 scenario
// itself, expressed as a unit test: a cert-manager Certificate's
// status.renewalTime, ~41 minutes in the future relative to `now`, must come
// back with a positive renewalTimeSecondsUntil — not left for the model to
// derive (incorrectly, as it did live) from two raw timestamp strings.
func TestAnnotateRelativeTimestamps_FutureFacingField(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 32, 11, 0, time.UTC)
	renewalTime := now.Add(41 * time.Minute).Format(time.RFC3339)

	obj := map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"status": map[string]any{
			"renewalTime": renewalTime,
		},
	}

	out := annotateRelativeTimestamps(now, obj).(map[string]any)
	status := out["status"].(map[string]any)

	if status["renewalTime"] != renewalTime {
		t.Errorf("status.renewalTime = %v, want the raw timestamp unchanged (%q)", status["renewalTime"], renewalTime)
	}
	got, ok := status["renewalTimeSecondsUntil"].(int64)
	if !ok {
		t.Fatalf("status.renewalTimeSecondsUntil missing or wrong type: %+v", status)
	}
	if want := int64(41 * 60); got != want {
		t.Errorf("status.renewalTimeSecondsUntil = %d, want %d (positive — still ahead of now, the opposite of what BUGS.md 105's investigation concluded)", got, want)
	}
}

// TestAnnotateRelativeTimestamps_PastFacingField exercises the "since" half
// of the same mechanism against a nested condition, matching the shape a
// real object's status.conditions[].lastTransitionTime takes.
func TestAnnotateRelativeTimestamps_PastFacingField(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 32, 11, 0, time.UTC)
	transition := now.Add(-2 * time.Hour).Format(time.RFC3339)

	obj := map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{
					"type":               "Ready",
					"status":             "True",
					"lastTransitionTime": transition,
				},
			},
		},
	}

	out := annotateRelativeTimestamps(now, obj).(map[string]any)
	conditions := out["status"].(map[string]any)["conditions"].([]any)
	cond := conditions[0].(map[string]any)

	got, ok := cond["lastTransitionTimeSecondsSince"].(int64)
	if !ok {
		t.Fatalf("conditions[0].lastTransitionTimeSecondsSince missing or wrong type: %+v", cond)
	}
	if want := int64(2 * 60 * 60); got != want {
		t.Errorf("lastTransitionTimeSecondsSince = %d, want %d (positive — already happened)", got, want)
	}
}

// TestAnnotateRelativeTimestamps_IgnoresUnrecognizedAndMalformedFields checks
// the function only ever ADDS a sibling key for a field it recognizes and can
// parse — it must never touch an unrelated string field, and a value that
// merely happens to share a recognized field's NAME but isn't a valid RFC3339
// string must be left alone rather than erroring or panicking.
func TestAnnotateRelativeTimestamps_IgnoresUnrecognizedAndMalformedFields(t *testing.T) {
	now := time.Now().UTC()
	obj := map[string]any{
		"metadata": map[string]any{
			"name":              "web",
			"creationTimestamp": "not-a-real-timestamp",
		},
		"spec": map[string]any{
			"replicas": float64(3),
		},
	}

	out := annotateRelativeTimestamps(now, obj).(map[string]any)
	metadata := out["metadata"].(map[string]any)
	if _, present := metadata["creationTimestampSecondsSince"]; present {
		t.Errorf("a malformed creationTimestamp must not get a computed sibling field, got %+v", metadata)
	}
	if metadata["name"] != "web" {
		t.Errorf("unrelated field metadata.name was altered: %+v", metadata)
	}
	spec := out["spec"].(map[string]any)
	if spec["replicas"] != float64(3) {
		t.Errorf("unrelated field spec.replicas was altered: %+v", spec)
	}
}

// TestAnnotateRelativeTimestamps_Boundary pins the exact-same-second edge case
// BACKLOG.md C9 calls out explicitly: a timestamp in the same second as `now`
// must compute to 0, not be pushed to +1/-1 by rounding.
func TestAnnotateRelativeTimestamps_Boundary(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 32, 11, 0, time.UTC)
	obj := map[string]any{
		"status": map[string]any{
			"renewalTime": now.Format(time.RFC3339),
		},
	}
	out := annotateRelativeTimestamps(now, obj).(map[string]any)
	status := out["status"].(map[string]any)
	if got := status["renewalTimeSecondsUntil"].(int64); got != 0 {
		t.Errorf("renewalTimeSecondsUntil for a timestamp equal to now = %d, want exactly 0", got)
	}
}
