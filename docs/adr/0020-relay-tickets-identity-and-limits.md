# 0020. Relay tickets, relay identity, and relay limits

Status: Accepted
Date: 2026-11-06

Refines [ADR 0011](0011-trust-root-and-key-hierarchy.md). Settles [#2](https://github.com/meerkat-mft/mmft/issues/2).

## Context

[ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md) sends a delivery between two agents with no direct path through a blind relay, which forwards sealed bytes without storing them. The relay needs three things that no earlier ADR settles:

- A way to know which two agents may meet for which delivery. The relay has no database and shouldn't call the orchestrator for each stream.
- An identity that agents can check. ADR 0011 lists 24-hour connection certificates for the relay. The orchestrator can issue those for itself, because it holds the CA key. The relay doesn't, and giving it a renewal path adds a second enrollment flow to M1.
- Bounds on what it holds open, which #2 asked for.

## Decision

**Relay tickets.** The orchestrator holds a separate Ed25519 relay ticket key beside its connection CA, so neither key ever signs the other's kind of message. It signs a ticket for each side of a delivery. A ticket names:

- the delivery
- the side: send or receive
- the agent that holds it, and the agent on the other side
- an expiry 15 minutes after issue

The signature covers a fixed context string followed by the payload. The relay accepts a stream only when the ticket's signature is valid, it hasn't expired, the holder matches the agent ID in the stream's connection certificate, the side matches the call, and the delivery matches the stream's. It pairs two sides only when each names the other. A ticket can be used again until it expires, which is how an agent reconnects and resumes. A pair that is already forwarding carries on after its tickets expire.

**Relay identity.** The relay has its own long-lived TLS key and a self-signed certificate. It gets no connection certificate. The orchestrator sends the SHA-256 of the relay's certificate in each `RelayTicket`, over the agent's authenticated stream, and the agent connects only to a relay that presents that certificate. The relay checks agents' connection certificates against the connection CA certificate, which is public. TLS 1.3 is required.

**Pairing and resume.** Whichever side arrives first waits for the other. The receiver states how many bytes of the sealed file it already holds, and the sender starts there. The relay forwards one message at a time and keeps no copy. The receiver acknowledges bytes once they are synced to disk, and the relay passes the acknowledgements to the sender. A stream ends cleanly only when the receiver has acknowledged the whole file. A new stream from the same agent, for the same delivery, side, and other agent, replaces the old one, so a half-open connection doesn't block a resume. Any other agent is refused. The receiving agent takes no more bytes than the size in the signed manifest.

**Limits.**

| Limit | Default | When reached |
| --- | --- | --- |
| Pairs forwarding per relay | 256 | `RESOURCE_EXHAUSTED` |
| Sides waiting for the other side, per relay | 512 | `RESOURCE_EXHAUSTED` |
| Open relay streams per agent | 16 | `RESOURCE_EXHAUSTED` |
| Wait for the first message on a stream | 30 seconds | `DEADLINE_EXCEEDED` |
| Wait for the other side | 2 minutes | `DEADLINE_EXCEEDED` |
| Pair with no data or acknowledgement | 60 seconds | `DEADLINE_EXCEEDED` |
| Data message size | 1 MiB | `RESOURCE_EXHAUSTED` |
| Connections per relay | 1024 | Further connections wait to be accepted |
| Bandwidth | No rate limit | HTTP/2 flow control shares it between streams |
| Sealed file size | No relay limit | The agents' spools set it |

## Alternatives considered

- **The relay asks the orchestrator about each stream:** checks revocation at once, but the relay then needs a database or a call path, and a busy orchestrator stalls every delivery.
- **Tickets signed with the connection CA key:** one key fewer, but the CA key would then sign two kinds of message, and a flaw in one format could be used against the other.
- **A shared secret between the orchestrator and relay:** simpler, but a compromised relay could then mint tickets.
- **A connection certificate for the relay, as ADR 0011 listed:** fits the table, but needs a way for the relay to get and renew a certificate without the CA key. Pinning by hash needs neither, and trust in the relay still comes from the orchestrator's authenticated stream.
- **A bandwidth limit per agent:** protects one agent's share, but there is no data yet to set it from, and the network can shape traffic meanwhile.

## Consequences

- The relay stays stateless. Restarting it ends the pairs it holds, and their agents resume from their byte offsets.
- The relay can't see revocations. A revoked agent can open relay streams until its ticket expires, up to 15 minutes, and a pair already forwarding runs to the end. The orchestrator issues no tickets to agents that aren't approved.
- A compromised orchestrator can issue tickets and point agents at another relay, as it can already impersonate connections. File contents stay sealed end to end.
- A compromised relay can drop, truncate, or alter bytes. It can't use a ticket itself, because a ticket is worthless without the holder's connection key. The signed manifest and the sealed file hash catch every change, as [ADR 0010](0010-age-sealed-files.md) requires, and the lab's failure tests T1 to T3 check this.
- Changing the relay's key means updating the hash in the orchestrator's settings. Agents get the new hash with their next ticket.
- We'll revisit the limits once metrics show real throughput and concurrency, and add a per-agent bandwidth share if one agent can starve others.
