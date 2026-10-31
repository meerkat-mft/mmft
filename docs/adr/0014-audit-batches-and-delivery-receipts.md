# 0014. Audit batches and two-sided delivery evidence

Status: Accepted
Date: 2026-10-31

Supersedes the per-event signing in [ADR 0008](0008-verifiable-audit-trail.md). The rest of ADR 0008 stands.

## Context

ADR 0008 says agents sign their audit events. With hybrid signatures, signing each record makes a log of 1 million 500-byte records grow from 532 MB to 3.9 GB. Threat model finding F4 adds that one agent's report proves only what that agent claims.

## Decision

Each agent keeps its own hash chain of audit events, and signs an **audit batch** statement covering the chain head, position, and event count. It flushes at 1,000 events or 60 seconds, whichever comes first, and only when there are new events.

A delivery counts as verified only with two signed statements: the source agent's delivery manifest and the destination agent's **delivery receipt**. The receipt records the delivery, the sealed file hash the destination computed itself, and the result. The orchestrator shows any delivery without both as unverified.

The orchestrator chains what it receives, and its audit checkpoints cover each agent's latest signed batch. It exports checkpoints every 5 minutes, using a key issued by an administrator key.

## Alternatives considered

- **Hybrid signatures on every event:** the strongest timing, but it makes logs about 7.3 times larger.
- **Ed25519 on every event, hybrid on batches:** smaller, but it adds a second mechanism for little gain.
- **Longer batch windows:** smaller still, but they widen the period where events are unsigned.
- **Destination reports only:** simpler, but it trusts one side.

## Consequences

Storage grows by at most about 1.9 GB per signer each year, however many events there are, plus a receipt of about 5 KB per delivery. A compromised agent can alter its unsigned events from the last 60 seconds or 1,000 events, and can always lie about its own actions, but it can't change what it has already signed, and it can't make the other agent's statement agree. Two colluding agents can still produce false evidence. Evidence appears slightly later than the event. Verifying an audit trail checks chains and batches, so verification stays fast.
