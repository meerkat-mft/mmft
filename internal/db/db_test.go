package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool returns a pool using a fresh schema. Set MMFT_TEST_DATABASE_URL to run
// these tests. CI always sets it.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("MMFT_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("MMFT_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("MMFT_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := Open(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func files(names ...string) fstest.MapFS {
	out := fstest.MapFS{}
	for i := 0; i+1 < len(names); i += 2 {
		out[names[i]] = &fstest.MapFile{Data: []byte(names[i+1])}
	}
	return out
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var regclass *string
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1)::text`, name).Scan(&regclass); err != nil {
		t.Fatal(err)
	}
	return regclass != nil
}

func TestEmbeddedMigrationsApplyAndRepeat(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied = %d", applied)
	}
	for _, table := range []string{"workspaces", "agents", "agent_identities", "agent_presence", "enrollment_tokens", "signed_statements", "runs", "deliveries", "delivery_files"} {
		if !tableExists(t, pool, table) {
			t.Errorf("%s is missing", table)
		}
	}
	applied, err = Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("repeat run applied %d", applied)
	}
}

// fixture creates a workspace, two agents, and a run, and returns their IDs.
type fixture struct{ workspace, a, b, run string }

func newFixture(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	if _, err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := pool.QueryRow(ctx, `INSERT INTO workspaces (name) VALUES ('finance') RETURNING id`).Scan(&f.workspace); err != nil {
		t.Fatal(err)
	}
	agent := `INSERT INTO agents (workspace_id, name, status) VALUES ($1, $2, 'approved') RETURNING id`
	if err := pool.QueryRow(ctx, agent, f.workspace, "a").Scan(&f.a); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, agent, f.workspace, "b").Scan(&f.b); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO runs (workspace_id, status) VALUES ($1, 'running') RETURNING id`, f.workspace).Scan(&f.run); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) delivery(ctx context.Context, pool *pgxpool.Pool, columns string, values ...any) error {
	args := append([]any{f.run, f.a, f.b}, values...)
	marks := []string{"$1", "$2", "$3"}
	for i := range values {
		marks = append(marks, fmt.Sprintf("$%d", i+4))
	}
	_, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, %s) VALUES (%s)`, columns, strings.Join(marks, ", ")), args...)
	return err
}

func TestSchemaRejectsBadRows(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	hash := make([]byte, 32)
	if _, err := pool.Exec(ctx, `INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, 't', '\x00')`, hash); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) func() error {
		return func() error {
			_, err := pool.Exec(ctx, sql, args...)
			return err
		}
	}
	key32, key1952 := make([]byte, 32), make([]byte, 1952)
	identity := `INSERT INTO agent_identities (agent_id, ed25519_public_key, mldsa65_public_key, encryption_recipient) VALUES ($1, $2, $3, 'r')`
	if err := exec(identity, f.a, key32, key1952)(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func() error{
		"workspace name":       exec(`INSERT INTO workspaces (name) VALUES ('bad name')`),
		"repeated workspace":   exec(`INSERT INTO workspaces (name) VALUES ('finance')`),
		"agent status":         exec(`INSERT INTO agents (workspace_id, name, status) VALUES ($1, 'c', 'hacked')`, f.workspace),
		"repeated agent":       exec(`INSERT INTO agents (workspace_id, name, status) VALUES ($1, 'a', 'approved')`, f.workspace),
		"unknown workspace":    exec(`INSERT INTO agents (workspace_id, name, status) VALUES (uuidv7(), 'c', 'approved')`),
		"second active key":    exec(identity, f.a, key32, key1952),
		"short Ed25519 key":    exec(identity, f.b, []byte{1}, key1952),
		"short ML-DSA key":     exec(identity, f.b, key32, []byte{1}),
		"identity no expiry":   exec(`INSERT INTO agent_identities (agent_id, ed25519_public_key, mldsa65_public_key, encryption_recipient, identity_statement_id) VALUES ($1, $2, $3, 'r', $4)`, f.b, key32, key1952, hash),
		"short token hash":     exec(`INSERT INTO enrollment_tokens (token_sha256, workspace_id, agent_name, expires_at) VALUES ('\x00', $1, 'a', now())`, f.workspace),
		"token used by nobody": exec(`INSERT INTO enrollment_tokens (token_sha256, workspace_id, agent_name, expires_at, used_at) VALUES ($1, $2, 'a', now(), now())`, hash, f.workspace),
		"run status":           exec(`INSERT INTO runs (workspace_id, status) VALUES ($1, 'nope')`, f.workspace),
		"flow without version": exec(`INSERT INTO runs (workspace_id, status, flow_id) VALUES ($1, 'pending', uuidv7())`, f.workspace),
		"delivery to itself":   exec(`INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status) VALUES ($1, $2, $2, 'pending')`, f.run, f.a),
		"delivery without run": exec(`INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status) VALUES (uuidv7(), $1, $2, 'pending')`, f.a, f.b),
		"unknown agent":        exec(`INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status) VALUES ($1, $2, uuidv7(), 'pending')`, f.run, f.a),
		"delivery status":      func() error { return f.delivery(ctx, pool, "status", "nope") },
		"evidence":             func() error { return f.delivery(ctx, pool, "status, evidence", "pending", "nope") },
		"short sealed hash":    func() error { return f.delivery(ctx, pool, "status, sealed_sha256", "pending", []byte{1}) },
		"raw error text":       func() error { return f.delivery(ctx, pool, "status, error_code", "failed", "Permission denied: /etc") },
		"verified, no receipt": func() error {
			return f.delivery(ctx, pool, "status, evidence, manifest_statement_id, sealed_sha256", "verifying", "verified", hash, hash)
		},
		"verified, no manifest": func() error {
			return f.delivery(ctx, pool, "status, evidence, receipt_statement_id, sealed_sha256", "verifying", "verified", hash, hash)
		},
		"verified, no hash": func() error {
			return f.delivery(ctx, pool, "status, evidence, manifest_statement_id, receipt_statement_id", "verifying", "verified", hash, hash)
		},
		"source only, no manifest": func() error {
			return f.delivery(ctx, pool, "status, evidence, sealed_sha256", "verifying", "source_only", hash)
		},
		"succeeded without evidence": func() error { return f.delivery(ctx, pool, "status", "succeeded") },
	}
	for name, try := range bad {
		if try() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := f.delivery(ctx, pool, "status, evidence, manifest_statement_id, receipt_statement_id, sealed_sha256", "succeeded", "verified", hash, hash, hash); err != nil {
		t.Fatalf("a complete delivery was rejected: %v", err)
	}
}

func TestDefaultIDsAreUUIDv7(t *testing.T) {
	pool := testPool(t)
	f := newFixture(t, pool)
	for _, id := range []string{f.workspace, f.a, f.run} {
		if len(id) != 36 || id[14] != '7' {
			t.Errorf("id %q is not UUIDv7", id)
		}
	}
}

func TestFileNamesCanBeDeletedWithoutTouchingEvidence(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status) VALUES ($1, $2, $3, 'pending') RETURNING id`, f.run, f.a, f.b).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO delivery_files (delivery_id, file_name) VALUES ($1, 'jan-jansen-payroll.csv')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM delivery_files WHERE delivery_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE id = $1`, id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("deleting a file name removed the delivery")
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND column_name = 'file_name' AND table_name <> 'delivery_files'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 0 {
		t.Fatal("file_name exists outside delivery_files")
	}
}

func TestSensitiveColumnsDoNotExist(t *testing.T) {
	pool := testPool(t)
	newFixture(t, pool)
	var found []string
	rows, err := pool.Query(context.Background(), `SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND column_name ~ '(password|passphrase|secret|private|seed|plaintext|content)'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		found = append(found, name)
	}
	if len(found) != 0 {
		t.Fatalf("sensitive columns: %v", found)
	}
}

func TestUpdatedAtFollowsChanges(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	var before, after time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM runs WHERE id = $1`, f.run).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `UPDATE runs SET status = 'succeeded' WHERE id = $1 RETURNING updated_at`, f.run).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.After(before) {
		t.Fatalf("updated_at did not move: %v, %v", before, after)
	}
}

func TestForeignKeysAreIndexed(t *testing.T) {
	pool := testPool(t)
	newFixture(t, pool)
	rows, err := pool.Query(context.Background(), `
		SELECT c.conrelid::regclass::text || '.' || a.attname
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		WHERE c.contype = 'f' AND c.connamespace = current_schema()::regnamespace
		AND NOT EXISTS (
			SELECT 1 FROM pg_index i
			WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1]
		)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		t.Errorf("foreign key without an index: %s", name)
	}
}

func TestConcurrentMigrationsApplyOnce(t *testing.T) {
	pool := testPool(t)
	var wg sync.WaitGroup
	results := make([]int, 8)
	errs := make([]error, 8)
	for i := range 8 {
		wg.Go(func() {
			results[i], errs[i] = Migrate(context.Background(), pool)
		})
	}
	wg.Wait()
	total := 0
	for i := range 8 {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		total += results[i]
	}
	if total != 1 {
		t.Fatalf("applied %d times", total)
	}
}

func TestFailedMigrationRollsBackAndRetries(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	broken := files("0001_a.sql", "CREATE TABLE a (id INT);", "0002_b.sql", "CREATE TABLE half (id INT); SELECT nonsense;")
	applied, err := migrate(ctx, pool, broken)
	if err == nil || applied != 1 {
		t.Fatalf("applied = %d, err = %v", applied, err)
	}
	if tableExists(t, pool, "half") {
		t.Fatal("failed migration left a table")
	}
	fixed := files("0001_a.sql", "CREATE TABLE a (id INT);", "0002_b.sql", "CREATE TABLE half (id INT);")
	if applied, err := migrate(ctx, pool, fixed); err != nil || applied != 1 {
		t.Fatalf("retry: applied = %d, err = %v", applied, err)
	}
	if !tableExists(t, pool, "half") {
		t.Fatal("retry did not apply")
	}
}

func TestLockIsReleasedAfterFailure(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := migrate(ctx, pool, files("0001_a.sql", "nonsense")); err == nil {
		t.Fatal("bad SQL accepted")
	}
	if _, err := migrate(ctx, pool, files("0001_a.sql", "SELECT 1;")); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryIsProtected(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	one := files("0001_a.sql", "SELECT 1;")
	two := files("0001_a.sql", "SELECT 1;", "0002_b.sql", "SELECT 2;")
	if _, err := migrate(ctx, pool, two); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate(ctx, pool, one); !errors.Is(err, ErrDatabaseNewer) {
		t.Fatalf("older binary: %v", err)
	}
	edited := files("0001_a.sql", "SELECT 3;", "0002_b.sql", "SELECT 2;")
	if _, err := migrate(ctx, pool, edited); !errors.Is(err, ErrChangedHistory) {
		t.Fatalf("edited migration: %v", err)
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"bad name":     files("first.sql", "x"),
		"no number":    files("000a_x.sql", "x"),
		"gap":          files("0001_a.sql", "x", "0003_b.sql", "x"),
		"starts late":  files("0002_a.sql", "x"),
		"same version": files("0001_a.sql", "x", "0001_b.sql", "x"),
		"upper case":   files("0001_A.sql", "x"),
		"not sql":      files("0001_a.txt", "x"),
	} {
		if _, err := load(fsys); !errors.Is(err, ErrBadMigration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := load(files("0002_b.sql", "b", "0001_a.sql", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].version != 1 || got[1].version != 2 || got[0].checksum == got[1].checksum {
		t.Fatalf("load = %+v", got)
	}
}

func TestErrorsNeverRepeatTheURL(t *testing.T) {
	const secret = "hunter2hunter2"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, u := range []string{
		"postgres://mmft:" + secret + "@127.0.0.1:1/mmft?connect_timeout=1",
		"not a url " + secret,
		"postgres://mmft:" + secret + "@host:notaport/mmft",
	} {
		_, err := Open(ctx, u)
		if err == nil {
			t.Fatalf("connected to %q", u)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks the password: %v", err)
		}
	}
}
