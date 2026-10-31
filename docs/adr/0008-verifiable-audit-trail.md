# 0008. The audit trail is verifiable from outside the database

Status: Accepted, with per-event signing superseded by [ADR 0014](0014-audit-batches-and-delivery-receipts.md)
Date: 2026-10-31

## Context

The product's compliance value rests on evidence. A hash chain alone proves little, because someone with database access can rebuild the whole chain.

## Decision

Audit events are append-only and hash-chained. The orchestrator periodically exports signed audit checkpoints to customer-controlled storage or a SIEM, and a verify command checks the chain against them. Agents sign their audit events and buffer them while offline, and they start no new work once the buffer is full. Source and destination checksums are both recorded. Logs and errors sent to the orchestrator never include file contents.

## Alternatives considered

- **Plain append-only tables:** simple, but they prove nothing to an auditor.
- **A public ledger or transparency service:** strong, but too heavy for version 1 and awkward for customer-run installs.

## Consequences

Tampering after a checkpoint can be detected, and evidence survives loss of the orchestrator database. Customers must configure somewhere to send checkpoints. Offline agents can pause work rather than move files without evidence.
