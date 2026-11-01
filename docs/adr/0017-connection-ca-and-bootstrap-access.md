# 0017. Connection CA, bootstrap access, and agent key storage

Status: Accepted
Date: 2026-11-01

Refines [ADR 0011](0011-trust-root-and-key-hierarchy.md).

## Context

Enrollment needs a running orchestrator with TLS, a way for the CLI to authenticate before user accounts arrive in M3, and somewhere for an unattended agent to keep its keys. ADR 0011 left all three open.

## Decision

**Connection CA.** The orchestrator runs a small CA with an Ed25519 key, which it uses for its own server certificate and for 24-hour connection certificates. TLS 1.3 is required. The install command carries the CA's fingerprint, so an agent can trust the orchestrator from its first connection. This CA grants connection only. End-to-end trust always comes from the trust root.

**Bootstrap access.** Until M3, the REST API uses one random bootstrap token, set at deployment and held only as a SHA-256 hash. It's for preview use and is removed in M3. It can create enrollment tokens and store signed statements, but it can't approve anything, because approval needs an administrator key's signature.

**Agent keys.** Agent private keys are stored unencrypted in a file readable only by the agent's service account, because an unattended agent must start after a reboot with no person present. OS key stores are on the roadmap.

## Alternatives considered

- **Public CA certificates:** no private CA, but private networks often have no public names.
- **Trusting the first certificate seen:** simple, but a machine in the middle could impersonate the orchestrator during enrollment.
- **No authentication until M3:** simplest, but unacceptable even in a lab.
- **Passphrase-protected agent keys:** stronger at rest, but an agent couldn't restart unattended.

## Consequences

A compromised orchestrator can impersonate connections, as ADR 0011 already accepts. The CA key is stored unencrypted for now, for the same reason as agent keys. Anyone with the bootstrap token can create pending agents and read metadata, so it must be treated as a secret until M3 removes it. Backups of agent systems contain private keys, and the documentation must say so.
