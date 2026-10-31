# 0002. The orchestrator cannot read file contents or credentials

Status: Accepted
Date: 2026-10-31

## Context

Compliance benefits from a central view of every file, and routing files through a hub gives that view. But a hub that holds files, keys, and access to everything concentrates risk. Encryption at rest does not help if the running application can decrypt.

## Decision

The orchestrator sees everything except file contents and credentials. Files go directly from an agent to a destination wherever a connector can reach it. Two agents with no direct path use a blind relay: the source agent encrypts for the destination agent, and the relay forwards ciphertext without decrypting or storing it. Credentials are managed centrally but sealed to the agents that use them, so the orchestrator stores only ciphertext. Encryption uses an established audited format or library, never a custom design.

## Alternatives considered

- **All files through the orchestrator:** the strongest central inspection and custody, but it exposes file contents on compromise and creates a bottleneck.
- **Staging in customer storage:** no Meerkat data path, but it needs customer storage and is unavailable to agent-only installs. It stays on the roadmap.
- **Peer-to-peer agents:** efficient, but one side must accept inbound connections.
- **Credentials the orchestrator can read:** simpler, but a compromised orchestrator would hold every endpoint credential.

## Consequences

A compromised orchestrator or relay does not directly expose contents. The relay's bandwidth limits agent-to-agent throughput, and both agents must be online unless an encrypted spool is added. Central scanning requires an optional hub route later. Credentials cannot be viewed after entry, and a new agent needs them sealed again. Metadata remains visible and is treated as potentially personal data.
