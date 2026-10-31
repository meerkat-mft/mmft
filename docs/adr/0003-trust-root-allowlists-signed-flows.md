# 0003. Agents distrust the orchestrator through a trust root, allowlists, and signed flows

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md) stops the orchestrator reading files, but a compromised orchestrator could still instruct agents to send files to an attacker, or swap public keys to read relayed files.

## Decision

Setup generates an offline, customer-held trust root that the orchestrator never holds. Agent identities are signed under it, enrollment includes an administrator signing step, and agents verify each other's keys against it. Each agent keeps a local allowlist of paths and destinations that the orchestrator cannot change remotely. Agents run only flows signed by an administrator. Agent updates are signed with a separate release key and started by an administrator.

## Alternatives considered

- **Trusting the orchestrator as certificate authority:** the most convenient option, but a compromised orchestrator could then read relayed files.
- **Allowlists without signed flows:** protects against exfiltration outside the list, but a compromised orchestrator could still reorder permitted destinations.

## Consequences

Meerkat can truthfully say the orchestrator cannot read files. Enrollment and flow changes need extra administrator steps, and losing the trust root requires a recovery procedure. Describe the orchestrator as holding no files, not as harmless if compromised.
