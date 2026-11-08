# Data model

This describes what the orchestrator stores and why, for Postgres 18. Terms follow [GLOSSARY.md](../GLOSSARY.md). Decisions are in [ADR 0016](adr/0016-data-model-foundations.md).

## Requirements

- The orchestrator never stores file contents, plaintext credentials, or private keys.
- Signed statements are stored as exact bytes, because a signature covers exact bytes.
- Audit evidence must survive the deletion of personal data.
- File names can be personal data, and are deletable on their own.
- The design ceiling is 1 million deliveries a day, kept for 13 months, which is about 400 million rows. This is an upper bound, not a measurement.

## Entities

| Table | Purpose | Changes | Retention |
| --- | --- | --- | --- |
| `workspaces` | Groups agents and runs | Rarely | Life of the install |
| `enrollment_tokens` | One-use enrollment tokens, stored as hashes | Used once | Delete soon after expiry |
| `agents` | One row per agent | Status changes | Life of the agent |
| `agent_identities` | Each agent's keys and identity statements over time | Revoked, never edited | Kept with audit evidence |
| `agent_presence` | Last contact, version, and allowlist hash | Constantly | Life of the agent |
| `signed_statements` | Every signed statement, as received | Never | Kept with audit evidence |
| `flows` | One row per flow: its workspace, name, and retirement | Rarely | Life of the install |
| `flow_versions` | Each version's exact payload, its status, and its approval | Status changes, payload never | Kept with audit evidence |
| `runs` | One row per trigger firing | Until finished | 13 months by default |
| `deliveries` | One file to one destination | Until finished | 13 months by default |
| `delivery_files` | The file name of a delivery | Deleted by retention | Customer setting, 13 months by default |
| `delivery_leases` | Each offer and lease of one side of a delivery | Extended until it ends | With its delivery |
| `delivery_events` | Every status change of a delivery | Never | With its delivery |
| `delivery_status_transitions`, `run_status_transitions` | The allowed status changes | Only by migration | Life of the install |

```text
workspaces ─┬─ agents ─┬─ agent_identities
            │          └─ agent_presence
            ├─ enrollment_tokens
            ├─ flows ─┬─ flow_versions ─── signed_statements (approval)
            │         └─ signed_statements (retirement)
            └─ runs ─── deliveries ─┬─ delivery_files
                                    ├─ delivery_leases ─── agents
                                    ├─ delivery_events
                                    └─ signed_statements (manifest, receipt)
```

Every delivery belongs to a run, including a manual one. A run of a flow names the flow version it ran, through a foreign key on `runs (flow_id, flow_version)`. A manual run leaves both empty.

A manual run, as ADR 0021 defines, fills the tables as follows:

- **`runs`:** a row in the agents' shared workspace, with no flow.
- **`deliveries`:** one row, which moves through the statuses below. Its `size_bytes` and `sealed_sha256` describe the sealed file, as the manifest states them.
- **`delivery_files`:** one row with the bare file name. It is the only place the name is stored.
- **`delivery_leases`:** one row for the send side and one for the receive side, once each is offered.
- **`signed_statements`:** the manifest and the receipt, each linked from the delivery.

## Delivery and run statuses

The statuses and leases are defined in [ADR 0026](adr/0026-delivery-states-and-leases.md). The database enforces them: triggers reject any status change not listed in `delivery_status_transitions` or `run_status_transitions`, and a new delivery or run must start `pending`.

```text
pending ──▶ claimed ──▶ transferring ──▶ verifying ──▶ succeeded
   │           │             │               │
   └───────────┴─────────────┴───────────────┴──▶ failed (with error_code)
```

| Status | Meaning |
| --- | --- |
| `pending` | Waiting for both agents to be connected and the source to claim the send side |
| `claimed` | The source holds the send lease and seals the file |
| `transferring` | The manifest is stored, and the receive side is offered to the destination |
| `verifying` | The destination holds the whole sealed file and checks it |
| `succeeded` | The receipt matches the manifest, so the evidence is `verified` |
| `failed` | Ended without the file in place. `error_code` says why |
| `retry_wait`, `cancelled` | Reserved for retries and cancellation. No transition reaches them yet |

A run starts `pending`, becomes `running` when its first lease is granted, and ends once none of its deliveries is active:

- `succeeded` if every delivery succeeded,
- `failed` if none did,
- `partial_failure` otherwise.

The database refuses to end a run while one of its deliveries is still active.

**Leases.** Each row in `delivery_leases` is one offer of one side, and its ID is the work ID the agent claims. It is `offered_at` when created, and `granted_at` with an `expires_at` once claimed. Each accepted update moves `expires_at` forward. It ends once, with an `end_reason`:

- `released`: its side finished.
- `expired`: its agent went silent, which fails the delivery with `lease_expired`.
- `delivery_ended`: the delivery ended first.

A partial unique index allows one open lease per side. A retry gets a new row, so an old work ID can never act again. The table is kept apart from `deliveries`, with a lower fill factor, so that extending a lease doesn't rewrite the delivery row.

**Events.** A trigger writes a `delivery_events` row for every status change, with the old and new status and the error code, in the same transaction. The table is append-only: updates, deletes, and truncation are rejected. It holds no file name. It isn't hash-chained. Signed audit events come from the agents' audit batches.

## Signed statements

A statement's ID is the `Verified.ID` from `internal/statement`, which covers its type and payload but not its signatures, as ADR 0015 requires. The same statement is stored once, even when resent with its signatures reordered or its JSON reformatted, and the envelope keeps the exact bytes first received. An agent's ID isn't generated by the database: it is derived from the agent's keys, as ADR 0019 defines, so the orchestrator must store the agent under the ID it is given. Approving an agent stores its identity statement, links it from the agent's active `agent_identities` row with its expiry, and sets the agent to `approved`. That row's statement is set once. Renewal arrives with `mmft agent renew`.

## Flows and flow versions

A flow belongs to one workspace, and its name is unique there. Its versions are never edited, so a version number always means the same payload:

- **Saving a draft** builds the payload from the cards, as [ADR 0022](adr/0022-flow-version-format.md) defines, checks it with `internal/flow`, and stores it as exact bytes with its SHA-256 under the flow's next version number, as `draft`. Every agent it names must be approved and in the flow's workspace.
- **Storing an approval** requires the approval to verify against the certificates and root key it carries, and to sign exactly that version's payload, as [ADR 0023](adr/0023-approvals-carry-their-certificates.md) defines. The version becomes `approved`, and every older version of the flow becomes `superseded`. The approval is kept exactly as received, and its statement is also stored in `signed_statements`.
- **At most one version per flow is approved,** enforced by a partial unique index. Newer drafts stay `draft` until they are approved themselves.

The flow's name isn't part of the signed payload, so renaming a flow needs no new approval.

**Retiring a flow** stores its retirement on the `flows` row, exactly as received, with its statement in `signed_statements` and the time, as [ADR 0024](adr/0024-flow-retirement-statement.md) defines. The retirement must name the flow and its workspace. A retired flow takes no new drafts or approvals, and its versions stay as evidence.

## Personal data and evidence

Audit events are hash-chained, so a record can't change. They must therefore never hold a file name. They refer to the delivery ID and the sealed file hash, and the name lives only in `delivery_files`.

Deleting a name removes one row and breaks nothing. What remains proves that a delivery happened, without saying what the file was called. A sealed file hash can't be matched to a known file, because every seal uses a fresh key.

Delivery manifests and receipts must not contain file names either, because `signed_statements` is kept as evidence and can't be edited.

## Main queries

| Query | Served by |
| --- | --- |
| Find active deliveries | Partial index on active statuses |
| Find expired leases | Partial index on open, granted leases by `expires_at` |
| Find a delivery's open lease for one side | Partial unique index on `delivery_leases (delivery_id, side)` |
| List a delivery's status changes | `delivery_events (delivery_id)` |
| List a run's deliveries | `deliveries (run_id)` |
| Find an agent's deliveries | `deliveries (source_agent_id)` and `(destination_agent_id)` |
| Page through runs in a workspace | `runs (workspace_id, id DESC)` |
| Find the active identity of an agent | Partial unique index on `agent_identities` |
| Find a flow's approved version | Partial unique index on `flow_versions` |
| Find a version and the next version number | `flow_versions` primary key `(flow_id, version)` |
| Claim an enrollment token | Primary key |
| Check an agent's status on each agent call | Primary key |
| Delete expired tokens | Partial index on unused tokens by `expires_at` |
| Delete old file names | Primary key, because UUIDv7 IDs are time-ordered |

## Growth

At the ceiling, `deliveries` holds about 400 million rows, plus indexes. Most installs will stay far below this.

Partitioning `deliveries` by month is the planned path, once real volumes need it. It requires a change of primary key, because a partition key must be part of the primary key. That needs a planned migration of existing rows, and references to `deliveries` must change at the same time.

`agent_presence` is kept apart so that heartbeats don't rewrite rows holding keys. It uses a lower fill factor, so updates can stay on the same page. Each hello also records the SHA-256 of the agent's allowlist, `allowlist_sha256`, so a changed allowlist shows on the orchestrator ([ADR 0024](adr/0024-allowlist-file-and-enforcement.md)). It records only the hash, never the allowlist's contents.

## Still to design

- The audit event tables, in M2, and how `delivery_events` relates to them.
- Users, roles, and API tokens, in M3.
- Separate database roles for migrations and the running service.
- The retention job.
