# 0018. Enrollment proof, agent fingerprints, and identity chains

Status: Accepted
Date: 2026-11-03

Refines [ADR 0011](0011-trust-root-and-key-hierarchy.md) and [ADR 0017](0017-connection-ca-and-bootstrap-access.md).

## Context

[ADR 0015](0015-strict-signed-statement-profile.md) requires enrollment to prove that an agent holds its private keys. It points to #5 for this, but the requirement is tracked in [#15](https://github.com/meerkat-mft/mmft/issues/15). ADR 0011 has an administrator compare an agent's fingerprint before signing its identity, but doesn't say what the fingerprint covers. The public key fingerprint covers only the signing keys. If the agent's encryption recipient were left out, a compromised orchestrator could swap in its own recipient during enrollment and open sealed files, against [ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md). An agent verifying its identity also needs the chain back to the trust root, which nothing yet delivers.

## Decision

**Enrollment proof.** The agent signs its enrollment request as a signed statement of type `enrollment-request`, with both its Ed25519 and ML-DSA-65 keys. The payload holds the SHA-256 of the enrollment token, the agent name, all three public keys, and the SHA-256 of the connection certificate request. The orchestrator verifies the statement against the keys in the request itself, and checks that every field matches the request. It does this before it claims the token, so a bad request can't use up someone's token. The request's own signature proves the connection key.

**Agent fingerprint.** An agent's fingerprint is the hex SHA-256 of a version tag, the Ed25519 key, the ML-DSA-65 key, and the encryption recipient with a decimal length prefix. `mmft agent approve` compares this fingerprint, the agent ID, and the agent name with what was collected from the host, and signs only on an exact match.

**Identity chain.** An agent identity statement carries everything needed to verify it from a pinned root fingerprint: the agent's ID, workspace, name, keys, and validity, plus the signer's administrator certificate and the trust root's public key. A verifier checks the root key against its pinned fingerprint, the certificate against the root, and the identity against the certificate.

**Pinning the orchestrator.** The orchestrator sends the connection CA certificate after its server certificate, so a client holding only the CA fingerprint from the install command can verify it.

## Alternatives considered

- **Proof by signing the CSR's challenge alone:** the CSR proves only the connection key, which ADR 0011 keeps classical and trusts for nothing end to end.
- **A challenge and response round trip:** it proves possession too, but needs a second call and server state. Binding the token hash gives the same freshness, because each token works once.
- **Proving possession of the encryption key:** an agent that enrolls someone else's recipient can't open anything sent to it, and the fingerprint check stops the dangerous swap. It would need an encrypt and decrypt challenge for no gain.
- **Leaving the recipient out of the fingerprint:** a shorter value to compare, but it leaves the swap open.
- **Distributing administrator certificates and the root key separately:** smaller identities, but it needs new tables and a distribution path, and every verifier would depend on the orchestrator serving the right set.

## Consequences

An identity statement is larger, at about 9 KB, because it embeds the administrator certificate and root key. An identity signed by an automation key will embed that key's chain instead, when automation keys arrive. Changing the fingerprint definition later would mean comparing fingerprints again for every agent, so it has a version tag. The enrollment proof is Meerkat's own protocol on standard primitives, and is part of the external review ADR 0011 already calls for.
