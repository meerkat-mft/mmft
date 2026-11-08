# 0023. Approvals carry their signers' certificates

Status: Accepted
Date: 2026-11-07

Refines [ADR 0012](0012-signed-statements-and-flow-approval.md) and [ADR 0022](0022-flow-version-format.md).

## Context

An agent runs a flow version only if administrators approved it. To check that, the agent needs each signer's administrator certificate and the trust root key that issued it, which it checks against its own pinned fingerprint. The orchestrator pins no root ([ADR 0011](0011-trust-root-and-key-hierarchy.md)), so it can't prove trust itself. It can only refuse what is malformed or doesn't fit together.

For agent identities, [ADR 0018](0018-enrollment-proof-and-agent-fingerprint.md) puts the whole chain inside the signed payload: the administrator certificate and the root key. That doesn't work for flow versions. The payload is built before anyone signs it, and with four-eyes approval several administrators sign one payload, so it can't name its signers.

## Decision

An **approval** is a JSON object holding the signed statement, the certificates of the administrators who signed it, and the root public key that issued them:

```json
{
  "statement": { "payloadType": "application/vnd.mmft.flow-version+json;v=1", "payload": "…", "signatures": [] },
  "administrator_certificates": [ { "…": "an administrator key statement, signed by the root" } ],
  "root_ed25519": "…",
  "root_mldsa65": "…"
}
```

- **The certificates sit beside the statement, not inside its payload.** Each is signed by the root, so carrying it outside the signed bytes gives an attacker nothing to change. A forged certificate fails against the root, and a missing one leaves its signature uncounted.
- **The orchestrator checks consistency, not trust.** `trust.CheckApproval` verifies each certificate against the root key in the approval, and needs at least one administrator's signature on the statement. The orchestrator then stores the approval only if the statement signs exactly the payload bytes of the version it is filed under. This is the same strength of check as `trust.CheckIdentity`.
- **Agents check trust.** `trust.VerifyApproval` also requires the root key to match the agent's pinned fingerprint, and the number of distinct administrators set in the agent's allowlist.
- **The approval is kept exactly as received,** because it is evidence. The statement is also stored in `signed_statements`, like every other signed statement.
- **An approval holds at most eight certificates,** the most signatures one statement may have.

The same shape can carry any statement that administrators sign and agents verify, such as a flow retirement.

## Alternatives considered

- **Certificates inside the payload, as for identities:** keeps one signed object, but the payload can't name signers it doesn't know yet, and four-eyes approval would need one payload per signer.
- **Register administrator certificates with the orchestrator once, and look them up by key:** smaller approvals, but it adds a registry to keep current, and agents would depend on the orchestrator to tell them which certificate belongs to which key. A missing or swapped certificate would then be the orchestrator's choice.
- **Have the orchestrator pin the root:** it could check trust itself, but that makes it a party to approval decisions, which ADR 0009 keeps away from it. A compromised orchestrator would then be trusted on approvals.

## Consequences

- The orchestrator can never mark a version approved without an approval that signs exactly its payload, but a valid-looking approval from a foreign root would still be stored. Only agents decide whether it counts, so the console must not present a stored approval as proof of trust.
- An approval is larger than the statement alone, by about 7 KB per certificate.
- Re-signing an approved version produces the same statement, because a statement's ID covers only its type and payload ([ADR 0015](0015-strict-signed-statement-profile.md)). The first approval received is kept. Four-eyes approval will need the stored approval to grow as administrators countersign, which is decided with that feature.
