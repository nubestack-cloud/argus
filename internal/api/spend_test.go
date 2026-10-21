package api

import (
	"testing"
	"time"

	"argus/internal/settings"
)

func floatPtr(f float64) *float64 { return &f }

// fullPricingCfg is a Config with all three price fields set — the
// "pricing is configured" state SpendCeilingBreached's ceiling checks
// depend on (settings.Config.SpendCeilingActive/CostPricingConfigured).
func fullPricingCfg() settings.Config {
	return settings.Config{
		PricePerMillionInputTokens:  floatPtr(2),
		PricePerMillionCachedTokens: floatPtr(0.2),
		PricePerMillionOutputTokens: floatPtr(10),
	}
}

// TestSpendCeilingBreached exercises the pure ceiling-check logic this
// task's brief asked for explicitly: under ceiling, proceeds (false); at or
// over ceiling, breached (true); and — the case that makes the whole check
// meaningful rather than a trap — no pricing configured NEVER blocks,
// regardless of how high todaySpend or how low the ceiling.
func TestSpendCeilingBreached(t *testing.T) {
	cases := []struct {
		name          string
		cfg           settings.Config
		todaySpendUSD float64
		want          bool
	}{
		{"no ceiling configured at all: never breached", settings.Config{}, 1_000_000, false},
		{
			"ceiling configured but pricing NOT configured: never breached (a ceiling check against an always-0 total is meaningless, not a block)",
			settings.Config{DailySpendCeilingUsd: floatPtr(0.01)}, 1_000_000, false,
		},
		{"under the ceiling: not breached", withCeiling(fullPricingCfg(), 10), 5, false},
		{"exactly at the ceiling: breached (>=, not >)", withCeiling(fullPricingCfg(), 10), 10, true},
		{"over the ceiling: breached", withCeiling(fullPricingCfg(), 10), 10.01, true},
		{"zero spend, positive ceiling: not breached", withCeiling(fullPricingCfg(), 10), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SpendCeilingBreached(c.cfg, c.todaySpendUSD); got != c.want {
				t.Errorf("SpendCeilingBreached(cfg, %v) = %v, want %v", c.todaySpendUSD, got, c.want)
			}
		})
	}
}

// TestStartOfUTCDay is the regression guard for the day-boundary half of the
// timezone bug: TodaySpend's window used to be `date_trunc('day', now())`,
// which cuts the day in the Postgres SESSION time zone (unset anywhere in
// this deployment). A daily spend ceiling computed against the wrong
// boundary either stays breached past its reset or resets early and lets a
// second day's worth of spend through — see startOfUTCDay's own doc comment.
func TestStartOfUTCDay(t *testing.T) {
	jst := time.FixedZone("JST", 9*3600)
	pst := time.FixedZone("PST", -8*3600)

	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"already midnight UTC is idempotent",
			time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)},
		{"last nanosecond of the UTC day stays on that day",
			time.Date(2026, 8, 21, 23, 59, 59, 999999999, time.UTC),
			time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)},
		{"a clock ahead of UTC is normalized to the UTC day, not the local one",
			// 2026-08-22T08:30+09:00 == 2026-08-21T23:30Z
			time.Date(2026, 8, 22, 8, 30, 0, 0, jst),
			time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)},
		{"a clock behind UTC is normalized to the UTC day, not the local one",
			// 2026-08-20T17:30-08:00 == 2026-08-21T01:30Z
			time.Date(2026, 8, 20, 17, 30, 0, 0, pst),
			time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)},
		{"month boundary",
			time.Date(2026, 9, 1, 0, 0, 1, 0, time.UTC),
			time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := startOfUTCDay(c.in)
			if !got.Equal(c.want) {
				t.Errorf("startOfUTCDay(%s) = %s, want %s", c.in, got, c.want)
			}
			if got.Location() != time.UTC {
				t.Errorf("startOfUTCDay(%s) location = %v, want UTC", c.in, got.Location())
			}
			// The reported date and the queried window must never disagree:
			// handleGetSpendToday labels the response with
			// time.Now().UTC()'s calendar date.
			if want := c.in.UTC().Format("2006-01-02"); got.Format("2006-01-02") != want {
				t.Errorf("startOfUTCDay(%s) is on day %s, but the UTC day is %s",
					c.in, got.Format("2006-01-02"), want)
			}
		})
	}
}

func withCeiling(cfg settings.Config, ceiling float64) settings.Config {
	cfg.DailySpendCeilingUsd = &ceiling
	return cfg
}
