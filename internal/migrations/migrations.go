// Package migrations embeds the SQL migration files so the hub binary is
// self-contained (no separate migrations directory needs to ship alongside the
// binary/image — consistent with ADR-7's single multi-entrypoint image).
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
