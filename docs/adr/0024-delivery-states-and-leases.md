# 0024. Delivery states and leases

Status: Accepted
Date: 2026-11-08

Supersedes the run start, dispatch, and busy refusal in [ADR 0021](0021-manual-deliveries-in-m1.md). The rest of ADR 0021 stands.

## Context

M1 left two gaps. A delivery to an offline agent was refused rather than queued, and a run stayed `running` when an agent went silent. M2 must end every delivery in a known state even when an agent, the relay, or the orchestrator stops. Retries and resume come next, and must build on this without changing it.

## Decision

**Statuses.** A delivery moves `pending → claimed → transferring → verifying → succeeded`.

- `pending`: no agent holds the delivery.
- `claimed`: the source holds the send lease and seals the file.
- `transferring`: the manifest is stored, and the receive side is offered.
- `verifying`: the destination holds the whole sealed file.
- `succeeded`: the receipt matches the manifest.

Any status that hasn't ended can go to `failed`, which always carries an error code. `retry_wait` and `cancelled` stay in the schema with no transition into them, until retries and cancellation add theirs.

**The database enforces them.** The allowed changes are rows in `delivery_status_transitions` and `run_status_transitions`. Triggers reject any other change, and require a new delivery or run to start `pending`. A later migration adds rows rather than editing these. A run can't reach a final status while one of its deliveries is still active.

**Every change is recorded.** A trigger writes a row to the append-only `delivery_events` table for each status change, in the same transaction, with no file name.

**Leases per side.** Each side of a delivery (send and receive) is a unit of work with its own lease, held by one agent:

1. The orchestrator offers the work with a `WorkOffer` while the agent is connected. It offers the send side only when the destination is connected too, so the source never seals for an agent that isn't there. Offers repeat on each reconnect and on a 10-second sweep.
2. The agent claims with a `LeaseClaim`, only if it has room under its limit of 8. Claims still waiting for an answer count toward the limit.
3. One conditional update grants exactly one claim. The `LeaseResult` follows, then the assignment with its relay ticket. Granting the first lease moves the run to `running`.

Each offer is a new row with a new work ID, so a retry gets a new lease, and a claim or update from an earlier attempt can never act.

**Extension.** Leases last 60 seconds. Each `DeliveryUpdate` names its work ID and extends the lease, and an active side sends one every 20 seconds. A heartbeat doesn't extend a lease: it shows that the agent is connected, not that the work is moving. An update for a lease the agent doesn't hold is ignored. A side that finishes reports `side_done`, which releases its lease. The source releases once the destination confirms it holds the whole sealed file, so the source's lease can't expire while the destination verifies.

**Expiry.** The sweep fails a delivery with `lease_expired` when one of its leases passes its expiry. It sends `Cancel` to every agent still holding one of its leases, and each agent stops that side and removes its spooled file. Any other failure cancels the other side the same way. When the orchestrator starts, it extends every open lease by one lease period, so agents that couldn't reach it while it was down keep their work.

**Run outcome.** When a delivery ends, the same transaction locks the run row and checks whether any delivery is still active. If none is, the run is set to:

- `succeeded` if every delivery succeeded,
- `failed` if none did,
- `partial_failure` otherwise.

**Audit.** The `delivery_events` row is a record of each change, not yet an audit event. It isn't hash-chained or signed. The agents' signed audit batches of [ADR 0014](0014-audit-batches-and-delivery-receipts.md) add tamper-evident events for each side. The orchestrator's checkpoints then decide whether `delivery_events` joins their chain.

## Alternatives considered

- **One lease per delivery:** simpler, but both agents work at once during a transfer, so it can't tell which one went silent.
- **Heartbeats extend leases:** less traffic, but a stuck delivery on a live agent would hold its lease for ever.
- **Offering the send side while the destination is offline:** starts sooner, but the source seals and then waits at the relay until its ticket expires, and fails anyway.
- **Transitions checked only in code:** fewer moving parts, but any missed path, script, or later change could revive a finished delivery.
- **Expiry moving a delivery back to `pending`:** that is a retry, and it needs the retryable error rules that retries bring.
- **Waiting for signed audit events before recording changes:** keeps one mechanism, but leaves status changes unrecorded until then.

## Consequences

- A run can be created for agents that are offline, and it waits.
- `dispatch_failed` and the `agent_busy` failure are gone. A lost assignment or a full agent now ends in a lease that expires or work that waits.
- An agent that goes silent fails its delivery within about 70 seconds: the 60-second lease plus up to one 10-second sweep.
- A receipt that arrives after its lease expired is ignored. The file can then be in the inbox while the delivery shows `failed` with `source_only` evidence. Retries and idempotent placement close this gap.
- The source can still wait at the relay for up to the ticket's lifetime if the destination drops after the manifest. Its lease stays alive because it is working.
- The orchestrator assumes one instance holds all agent streams, as before.
- Status changes are now checked twice, in code and in the database. A new status or transition needs a migration.
