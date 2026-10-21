package health

import "testing"

func TestRank(t *testing.T) {
	order := []Level{LevelHealthy, LevelUnknown, LevelDegraded, LevelUnhealthy}
	for i := 1; i < len(order); i++ {
		if Rank(order[i-1]) >= Rank(order[i]) {
			t.Errorf("%s does not rank below %s", order[i-1], order[i])
		}
	}
	// Neutral is as benign as healthy; a word outside the vocabulary is
	// unknown, never healthy.
	if Rank(LevelNeutral) != Rank(LevelHealthy) || Rank("broken-ish") != Rank(LevelUnknown) {
		t.Errorf("neutral %d, stray %d", Rank(LevelNeutral), Rank("broken-ish"))
	}
}

func TestWorseOf(t *testing.T) {
	all := []Level{"", LevelHealthy, LevelNeutral, LevelUnknown, LevelDegraded, LevelUnhealthy}
	want := map[[2]Level]Level{
		{LevelHealthy, LevelNeutral}: LevelHealthy, // running beside switched-off reads healthy
		{LevelNeutral, LevelNeutral}: LevelNeutral, // only all switched-off reads neutral
		{"", ""}:                     "",
	}
	for _, a := range all {
		for _, b := range all {
			got := WorseOf(a, b)
			if got != WorseOf(b, a) {
				t.Errorf("WorseOf(%q,%q)=%q but reversed %q", a, b, got, WorseOf(b, a))
			}
			exp, special := want[[2]Level{a, b}]
			if !special {
				exp, special = want[[2]Level{b, a}]
			}
			if !special {
				switch {
				case a == "":
					exp = b
				case b == "":
					exp = a
				case Rank(a) >= Rank(b):
					exp = a
				default:
					exp = b
				}
			}
			if got != exp {
				t.Errorf("WorseOf(%q,%q) = %q, want %q", a, b, got, exp)
			}
		}
	}
}
