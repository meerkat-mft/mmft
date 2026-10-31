# Meerkat MFT product requirements

Status: Agreed for planning, 2026-10-31. Terms follow [GLOSSARY.md](../../GLOSSARY.md).

## Summary

Meerkat MFT orchestrates system-to-system file movement between sources and destinations that the customer owns. It decides what moves and when, and it records what happened. It owns no endpoints, listens on nothing public, and cannot read file contents or credentials.

Recent mass exploitation of internet-facing MFT servers is the problem this design answers. Meerkat's central claim is that the orchestrator controls everything but cannot read the sensitive parts.

## Project context

- **Eventual audience:** mid-sized regulated EU companies, on any public or private cloud.
- **Licence:** AGPL, keeping the right to relicense. See [ADR 0007](../adr/0007-agpl-licence.md).

## Principles

1. The customer brings every source and destination.
2. Nothing Meerkat runs listens on the public internet.
3. The orchestrator sees everything except file contents and credentials.
4. A compromised orchestrator must not be able to expose or exfiltrate files on its own.
5. Every capability is available through the public API.
6. No file moves without evidence.
7. Trust and reliability come before interface polish.

## Version 1 scope

### In scope

- Orchestrator, relay, agent, console, API, and CLI, deployed with Docker Compose.
- Agents for Linux and Windows, one per system, connecting outbound only.
- The local files connector, behind a connector interface designed for later connectors.
- Agent-to-agent delivery through the blind relay, with end-to-end encryption.
- Flows drawn on a canvas as trees of cards, stored as signed, versioned JSON.
- Triggers: schedule, file arrival, and API call.
- Selection rules and conditions over file metadata, including a rule builder and CEL expressions.
- Safe pickup through polling, a stable-size check, and an optional marker file.
- Checksums at source and destination.
- Retries per delivery, resume after interruption, and at-least-once delivery with idempotent effect.
- A hash-chained audit trail with signed checkpoints exported outside the database.
- Agent enrollment, an offline trust root, agent allowlists, and admin-signed flows.
- Local accounts with TOTP MFA enforced at first login, plus fixed administrator, operator, and auditor roles.
- Scoped API tokens, webhooks, Prometheus metrics, structured logs, and SIEM export.
- Workspaces inside one organization per install.
- Configurable metadata and audit retention, with a 13-month default for metadata.
- Tested backup and restore, with published recovery targets.
- A control matrix mapping product controls to GDPR, NIS2, and DORA obligations.
- SBOMs, signed releases, admin-started agent updates, and a vulnerability process.

### Out of scope for version 1

Everything below is on the roadmap unless marked never.

- Remote connectors: SFTP, then S3, Azure Blob, and SMB.
- The bundled agent, which only matters once remote connectors exist.
- Sealed credentials, which ship with the first remote connector.
- PGP encryption and decryption.
- Staging storage as a route between agents.
- OIDC, SCIM, custom roles, and four-eyes approval.
- High availability and Kubernetes.
- Malware scanning, DLP, compression, and format translation, plus a hub route for inspection.
- Content-based rules and masking of file names.
- A partner web portal and ad hoc sharing.
- Multi-tenancy and SaaS.
- Never: loops, joins with waiting, or custom scripts in flows.

### Known limitations of version 1

- Files can only move between systems running an agent. A usual exchange with a partner's SFTP server needs the SFTP connector first.
- All traffic between two systems passes through the relay, so its bandwidth sets throughput.
- There is no automatic failover.

## How a flow runs

1. A trigger fires, and the orchestrator creates a run for a specific flow version.
2. The source agent claims the work under a lease and verifies the flow signature and its allowlist.
3. The agent applies the selection rule, confirms each file is complete, and evaluates conditions to choose a path.
4. The agent encrypts each file so that only the destination agent can read it, and sends it through the relay.
5. The destination agent decrypts the file, verifies its checksum, and places it safely.
6. Each delivery reports its result, and each state change writes an audit event.
7. Source clean-up happens only after every delivery succeeds. Files that match no path stay in place and raise an alert.

## Compliance position

Laws such as GDPR, NIS2, and DORA bind organizations, not products. Meerkat is designed to support them and never claims to be compliant or certified. Evidence comes from product controls, the published control matrix, and vendor assurances. Metadata, including file names, can be personal data and is treated as such.

The EU Cyber Resilience Act may apply directly once Meerkat is sold. Confirm this with legal advice before any sale.

## Milestones

Estimates are guesses. Every milestone must pass failure tests covering killed processes, dropped networks, full disks, and expired certificates.

| Milestone | Scope | Done when | Estimate |
| --- | --- | --- | --- |
| **M0: Foundations** | ADRs, threat model, API sketch, CI with tests, linting, and SBOM | The design is written down and CI passes | 3-4 weeks |
| **M1: Skeleton** | Trust root, enrollment, mTLS stream, blind relay, one manual flow | A file moves between two lab VMs, and the orchestrator cannot read it | 2-3 months |
| **M2: Reliable runs** | State machine, retries, resume, audit chain and export, allowlists, signed flows | Killing any component mid-delivery loses no file and no evidence | 2-3 months |
| **M3: Operable** | Local auth with MFA, roles, schedules, triggers, rules, API tokens, console, read-only canvas | Flows run in the lab without touching the CLI | 4-6 months |
| **M4: Version 1** | Editable canvas, backup and restore, webhooks, metrics, SIEM export, docs, control matrix | Two agents run real scheduled flows unattended for a month, and a restore has been tested | 2-3 months |

## Repository layout

```text
mmft/
├── cmd/            # orchestrator, relay, agent, and CLI entry points
├── internal/       # flows, runs, audit, trust, relay, connectors, auth
├── api/            # OpenAPI spec and agent gRPC definitions
├── web/            # TypeScript console
├── deploy/compose/ # evaluation and production Compose files
├── lab/            # home lab setup and interoperability tests
└── docs/           # ADRs, threat model, compliance matrix
```
