# 0004. Postgres is the only required backend, with an explicit state machine

Status: Accepted
Date: 2026-10-31

## Context

The orchestrator needs configuration, scheduling, a job queue, run state, and an audit trail. A Compose install must stay small and simple to back up.

## Decision

Postgres holds all of these. Runs follow an explicit state machine, with deliveries tracked individually and each state change writing its audit event in the same transaction. Work is claimed through leases. The delivery guarantee is at-least-once with idempotent effect, and each connector declares what it can guarantee.

## Alternatives considered

- **Temporal:** excellent durable execution, but it adds several services and far more than linear flows need.
- **NATS or Redis as a queue:** faster, but two stores must be backed up and restored consistently.
- **Promising exactly-once delivery:** impossible across systems that fail independently.

## Consequences

There is one thing to run and restore, and state and evidence cannot drift apart. We write and test the state machine ourselves. Postgres is a single point of failure until high availability ships. Keep the state machine behind a small interface so it can be replaced.
