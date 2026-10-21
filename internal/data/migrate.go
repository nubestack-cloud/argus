package data

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // registers the "postgres://" driver
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"argus/internal/migrations"
)

// RunMigrations applies every pending migration (lld/05-data-model.md §8: expand →
// migrate → contract; golang-migrate, a pick made in that document since it's an
// implementation detail below the tracked-decision threshold). Returns whether any
// migration actually ran, so callers can distinguish "applied N migrations" from
// "already up to date" instead of logging the same message for both — a failed
// migration marks the tracked version dirty regardless of whether the underlying
// DDL rolled back (Postgres DDL is transactional per-file here, but golang-migrate
// can't assume that in general), so don't assume "no error" always meant "no-op."
func RunMigrations(connString string) (applied bool, err error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return false, fmt.Errorf("load embedded migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, connString)
	if err != nil {
		return false, fmt.Errorf("init migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			return false, nil
		}
		return false, fmt.Errorf("run migrations: %w", err)
	}
	return true, nil
}
