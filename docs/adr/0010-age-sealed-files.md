# 0010. Files are sealed with age and bound by a signed manifest

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md) requires end-to-end encryption between agents with an audited format or library. Threat model finding F3 requires that reordering, truncation, and replay all fail, and deliveries must resume after interruption. The relay and orchestrator are untrusted for confidentiality and integrity.

## Decision

Each delivery between agents uses one **sealed file**, which is the source file encrypted with the [age format](https://c2sp.org/age) through `filippo.io/age`, to the destination agent's hybrid post-quantum recipient (MLKEM768-X25519).

1. The source agent seals the file into its private spool, with a fresh file key for each delivery.
2. It signs a **delivery manifest** naming the delivery, flow version, source agent, destination agent, format version, and the sealed file's size and SHA-256. The signature uses the agent's identity key under the trust root.
3. It sends the sealed file through the relay as plain bytes. An interrupted transfer resumes from a byte offset.
4. The destination agent stores the sealed file in its private spool, checks the hash against the signed manifest, and only then decrypts it to a temporary name.
5. Each agent deletes its spooled copy after the delivery ends.

Audit records use the sealed file's SHA-256, not a hash of the plaintext.

## Alternatives considered

- **Streaming encryption without a spool:** needs less disk, but age output can't be reproduced after an interruption, because each seal uses a fresh key, so resume would restart the whole file.
- **Splitting files into separately sealed segments:** resumes without a full spool, but it is a custom construction that must solve ordering and truncation itself.
- **`crypto/hpke` with our own chunking:** standard parts, but a custom file format, which the project rules out.
- **Tink streaming AEAD:** a sound option, but it brings a larger dependency and no recipient format, so we would still design key wrapping.
- **Sign the plaintext hash:** familiar, but it lets anyone with the audit data test whether a delivery matches a known file.
- **X25519 recipients only:** smaller keys, but recorded relay traffic could become readable to a future quantum computer, and files can stay sensitive for years.

## Consequences

age's chunk counter and final-chunk flag detect reordering and truncation, and its authenticated encryption ties the plaintext to the sealed file. The signed hash adds what age lacks, because age does not authenticate the sender and anyone with a public key can create a valid file for that recipient. It also binds each sealed file to one delivery, which blocks replay.

Agents need free disk space for one sealed copy of each file in flight, and the destination briefly holds both copies. Providing that space is the customer's responsibility. An agent checks free space before sealing, and if there isn't enough, the delivery fails with a clear reason and a notification rather than filling the disk. Tampering is detected at the end of a transfer rather than at the chunk where it happens. Plaintext size stays visible, within a small overhead.

The format uses ChaCha20-Poly1305 and a post-quantum recipient based on an IETF draft. Neither is FIPS approved, so FIPS support would need a new format version, which the manifest's format version field allows. The canonical encoding and signature scheme of the manifest are settled with flow signing in [#8](https://github.com/meerkat-mft/mmft/issues/8), and agent keys in [#7](https://github.com/meerkat-mft/mmft/issues/7).
