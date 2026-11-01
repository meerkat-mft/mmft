// Package db connects to Postgres and applies forward-only migrations.
package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var embedded embed.FS

// migrationLock is the advisory lock key, so that only one process migrates.
const migrationLock = 7302814

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Errors returned by this package.
var (
	ErrInvalidURL     = errors.New("db: invalid database URL")
	ErrDatabaseNewer  = errors.New("db: database has migrations this version doesn't know, so it can't run against it")
	ErrChangedHistory = errors.New("db: an applied migration has changed")
	ErrBadMigration   = errors.New("db: invalid migration files")
)

// Open connects to Postgres. Errors never repeat the URL, which holds a password.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, ErrInvalidURL
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, ErrInvalidURL
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("db: cannot reach the database")
	}
	return pool, nil
}

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

func load(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, entry := range entries {
		match := migrationName.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("%w: %s", ErrBadMigration, entry.Name())
		}
		version, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadMigration, entry.Name())
		}
		body, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		out = append(out, migration{version, entry.Name(), string(body), hex.EncodeToString(sum[:])})
	}
	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("%w: expected version %d, found %s", ErrBadMigration, i+1, m.name)
		}
	}
	return out, nil
}

// Migrate applies the built-in migrations. It's safe to repeat, and safe for
// several processes to run at once.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied int, err error) {
	files, err := fs.Sub(embedded, "migrations")
	if err != nil {
		return 0, err
	}
	return migrate(ctx, pool, files)
}

func migrate(ctx context.Context, pool *pgxpool.Pool, files fs.FS) (applied int, err error) {
	migrations, err := load(files)
	if err != nil {
		return 0, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return 0, err
	}
	defer func() {
		// Unlock even if ctx was cancelled, as the connection returns to the pool.
		unlock, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, uerr := conn.Exec(unlock, `SELECT pg_advisory_unlock($1)`, migrationLock); uerr != nil {
			err = errors.Join(err, uerr)
		}
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return 0, err
	}
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	type record struct {
		Version  int
		Checksum string
	}
	history, err := pgx.CollectRows(rows, pgx.RowToStructByPos[record])
	if err != nil {
		return 0, err
	}
	if len(history) > len(migrations) {
		return 0, ErrDatabaseNewer
	}
	for i, h := range history {
		if h.Version != migrations[i].version || h.Checksum != migrations[i].checksum {
			return 0, fmt.Errorf("%w: version %d", ErrChangedHistory, h.Version)
		}
	}
	for _, m := range migrations[len(history):] {
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, m.version, m.name, m.checksum)
			return err
		}); err != nil {
			return applied, fmt.Errorf("db: migration %s failed: %w", m.name, err)
		}
		applied++
	}
	return applied, nil
}
