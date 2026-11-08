package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// deliveryStatuses are every status the deliveries table allows.
var deliveryStatuses = []string{"pending", "claimed", "transferring", "verifying", "retry_wait", "succeeded", "failed", "cancelled"}

// allowedDelivery are the status changes ADR 0026 allows. Any other must be
// rejected by the database, whatever code sends it.
var allowedDelivery = map[[2]string]bool{
	{"pending", "claimed"}:        true,
	{"claimed", "transferring"}:   true,
	{"transferring", "verifying"}: true,
	{"verifying", "succeeded"}:    true,
	{"pending", "failed"}:         true,
	{"claimed", "failed"}:         true,
	{"transferring", "failed"}:    true,
	{"verifying", "failed"}:       true,
}

// paths reach each status from pending through allowed changes.
var paths = map[string][]string{
	"pending":      nil,
	"claimed":      {"claimed"},
	"transferring": {"claimed", "transferring"},
	"verifying":    {"claimed", "transferring", "verifying"},
	"succeeded":    {"claimed", "transferring", "verifying", "succeeded"},
	"failed":       {"failed"},
}

// newDelivery inserts a pending delivery with full evidence and an error code,
// so that only the status rules can reject a change.
func newDelivery(t *testing.T, pool *pgxpool.Pool, f fixture) string {
	t.Helper()
	ctx := context.Background()
	hash := make([]byte, 32)
	if _, err := pool.Exec(ctx, `INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, 't', '\x00')
		ON CONFLICT DO NOTHING`, hash); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status, evidence,
		manifest_statement_id, receipt_statement_id, sealed_sha256, error_code)
		VALUES ($1, $2, $3, 'pending', 'verified', $4, $4, $4, 'test_code') RETURNING id`, f.run, f.a, f.b, hash).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDeliveriesChangeOnlyAsAllowed(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	for from, path := range paths {
		for _, to := range deliveryStatuses {
			if to == from {
				continue
			}
			id := newDelivery(t, pool, f)
			if err := walkDelivery(ctx, pool, id, path...); err != nil {
				t.Fatalf("reaching %s: %v", from, err)
			}
			_, err := pool.Exec(ctx, `UPDATE deliveries SET status = $2 WHERE id = $1`, id, to)
			if allowed := allowedDelivery[[2]string{from, to}]; allowed && err != nil {
				t.Errorf("%s to %s was rejected: %v", from, to, err)
			} else if !allowed && err == nil {
				t.Errorf("%s to %s was accepted", from, to)
			}
		}
	}
}

func TestDeliveriesAndRunsStartPending(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	for _, status := range deliveryStatuses[1:] {
		if err := f.delivery(ctx, pool, "status, error_code", status, "test_code"); err == nil {
			t.Errorf("a delivery started %s", status)
		}
	}
	for _, status := range []string{"running", "succeeded", "partial_failure", "failed", "cancelled"} {
		if _, err := pool.Exec(ctx, `INSERT INTO runs (workspace_id, status) VALUES ($1, $2)`, f.workspace, status); err == nil {
			t.Errorf("a run started %s", status)
		}
	}
}

func TestRunsChangeOnlyAsAllowed(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	set := func(run, status string) error {
		_, err := pool.Exec(ctx, `UPDATE runs SET status = $2 WHERE id = $1`, run, status)
		return err
	}
	newRun := func() string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO runs (workspace_id, status) VALUES ($1, 'pending') RETURNING id`, f.workspace).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	allowed := [][]string{
		{"running", "succeeded"}, {"running", "partial_failure"}, {"running", "failed"}, {"failed"},
	}
	for _, path := range allowed {
		run := newRun()
		for _, s := range path {
			if err := set(run, s); err != nil {
				t.Errorf("%v: to %s: %v", path, s, err)
			}
		}
	}
	rejected := [][]string{
		{"succeeded"}, {"partial_failure"}, {"running", "pending"}, {"failed", "running"},
		{"running", "succeeded", "failed"}, {"running", "failed", "succeeded"},
	}
	for _, path := range rejected {
		run := newRun()
		var err error
		for _, s := range path {
			if err = set(run, s); err != nil {
				break
			}
		}
		if err == nil {
			t.Errorf("%v was accepted", path)
		}
	}
}

func TestARunCantEndWhileADeliveryIsActive(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	done, active := newDelivery(t, pool, f), newDelivery(t, pool, f)
	if err := walkDelivery(ctx, pool, done, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := walkDelivery(ctx, pool, active, "claimed"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status = 'running' WHERE id = $1`, f.run); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status = 'failed' WHERE id = $1`, f.run); err == nil {
		t.Fatal("a run ended with a delivery still claimed")
	}
	if err := walkDelivery(ctx, pool, active, "failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status = 'failed' WHERE id = $1`, f.run); err != nil {
		t.Fatalf("a finished run could not end: %v", err)
	}
}

func TestEveryStatusChangeIsRecorded(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	id := newDelivery(t, pool, f)
	if err := walkDelivery(ctx, pool, id, "claimed", "transferring", "failed"); err != nil {
		t.Fatal(err)
	}
	// A change to another column records nothing.
	if _, err := pool.Exec(ctx, `UPDATE deliveries SET size_bytes = 10 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT coalesce(from_status, ''), to_status FROM delivery_events WHERE delivery_id = $1 ORDER BY id`, id)
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]string
	for rows.Next() {
		var e [2]string
		if err := rows.Scan(&e[0], &e[1]); err != nil {
			t.Fatal(err)
		}
		got = append(got, e)
	}
	rows.Close()
	want := [][2]string{{"", "pending"}, {"pending", "claimed"}, {"claimed", "transferring"}, {"transferring", "failed"}}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
	var code string
	if err := pool.QueryRow(ctx, `SELECT error_code FROM delivery_events WHERE delivery_id = $1 AND to_status = 'failed'`, id).Scan(&code); err != nil || code != "test_code" {
		t.Fatalf("the failure was recorded with %q: %v", code, err)
	}
	for name, sql := range map[string]string{
		"update":   `UPDATE delivery_events SET to_status = 'succeeded'`,
		"delete":   `DELETE FROM delivery_events`,
		"truncate": `TRUNCATE delivery_events`,
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Errorf("%s of delivery_events was accepted", name)
		}
	}
}

func TestLeasesAreOnePerSide(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newFixture(t, pool)
	id := newDelivery(t, pool, f)
	offer := `INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at) VALUES ($1, $2, $3, now())`
	if _, err := pool.Exec(ctx, offer, id, "send", f.a); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, offer, id, "receive", f.b); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, offer, id, "send", f.a); err == nil {
		t.Fatal("a second open lease for one side was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE delivery_leases SET ended_at = now(), end_reason = 'released' WHERE side = 'send'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, offer, id, "send", f.a); err != nil {
		t.Fatalf("a new lease after the old one ended was rejected: %v", err)
	}
	bad := map[string]string{
		"side":                `INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at) VALUES ($1, 'both', $2, now())`,
		"granted, no expiry":  `INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at, granted_at) VALUES ($1, 'send', $2, now(), now())`,
		"ended, no reason":    `INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at, ended_at) VALUES ($1, 'send', $2, now(), now())`,
		"expired, never held": `INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at, ended_at, end_reason) VALUES ($1, 'send', $2, now(), now(), 'expired')`,
	}
	for name, sql := range bad {
		if _, err := pool.Exec(ctx, sql, id, f.a); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
