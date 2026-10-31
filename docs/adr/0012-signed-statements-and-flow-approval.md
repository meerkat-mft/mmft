# 0012. Signed statements and flow approval

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0009](0009-trusted-approvals-in-the-cli.md) moves approval to the CLI, and [ADR 0010](0010-age-sealed-files.md) and [ADR 0011](0011-trust-root-and-key-hierarchy.md) need a signed format. The threat model adds requirements: stop replay and rollback (F2), and leave room for a second approver (F7). The project must not invent signature formats.

## Decision

### Format

Every signed object is a **signed statement** in a [DSSE](https://github.com/secure-systems-lab/dsse) JSON envelope. Signatures cover the exact payload bytes, so nothing is canonicalized. Each statement type has its own versioned payload type, such as `application/vnd.mmft.flow-version+json;v=1`, and a verifier states the type it expects.

A signer counts only if both its Ed25519 and its ML-DSA-65 signatures verify. Both are ordinary DSSE signatures in one envelope. Key identifiers are hints and are never used for security decisions.

### Who may sign what

| Statement | Signed by |
| --- | --- |
| Root rollover, administrator key | Trust root |
| Administrator key revocation | Trust root |
| Flow version | Administrator key |
| Automation key, audit checkpoint key | Administrator key |
| Agent identity | Administrator key or automation key |
| Automation key or agent revocation | Administrator key |
| Delivery manifest, delivery receipt, audit batch | Agent identity |
| Audit checkpoint | Audit checkpoint key |

Verifiers check the role as well as the signature, so an automation key can't approve a flow.

### Flow approval

1. The console or API saves a draft flow version.
2. `mmft flow approve` fetches the draft, verifies the last approved version, shows the difference, and signs. It can run from a script with a named version and its hash, so approval can be part of a reviewed pipeline.
3. Agents verify the statement before running that version.

The payload includes the flow's identity, workspace, an increasing version number, and the agents it names. Each agent's allowlist file sets how many approvers a flow needs, so a signer can't lower the number. In the MVP that is one, and four-eyes approval raises it without changing the format.

### Replay and rollback

- An agent records the highest approved version it has accepted for each flow and refuses anything lower.
- A signed retirement statement stops a flow permanently.
- Each delivery manifest and receipt names one delivery, so neither can be reused for another.
- An agent refuses an older signed release unless an operator overrides this on the host.

## Alternatives considered

- **Signed JSON with canonicalization:** familiar, but canonicalization is a known source of signature bugs.
- **JWS:** widely used, but it has a history of algorithm confusion and needs a separate form for multiple signatures.
- **COSE:** a strong standard, but it adds a binary format and has less Go tooling here.
- **X.509 for everything:** it doesn't fit flows, and hybrid signatures aren't settled in it.
- **Composite ML-DSA:** a single combined signature, but still a draft, and it targets X.509.

## Consequences

Meerkat uses a small published format with explicit type binding, and second approvers need no format change. Each statement adds about 4.6 KB. The rules around the envelope are still our own protocol, and need external review.

A compromised orchestrator can still withhold a new version, so an agent keeps running the last approved one, and can still trigger an approved flow at the wrong time. Both stay within approved paths and destinations, and are accepted risks. `mmft flow status` should compare what agents report with what was approved, so that withheld versions can be noticed.
