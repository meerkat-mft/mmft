# 0019. Agent IDs and workspaces come from the host

Status: Accepted
Date: 2026-11-05

Supersedes [ADR 0018](0018-enrollment-proof-and-agent-fingerprint.md).

## Context

[ADR 0018](0018-enrollment-proof-and-agent-fingerprint.md) has `mmft agent approve` sign an identity only when the fingerprint, agent ID, and agent name match the values collected from the host. The independent review of the enrollment set (see [#15](https://github.com/meerkat-mft/mmft/issues/15)) found that two of the signed values are still the orchestrator's choice:

- **The agent ID** is assigned by the orchestrator at enrollment, and the host only repeats it. A compromised orchestrator can give a second host the ID of an existing agent. That host's keys then get a valid identity under the existing agent's ID, with a different encryption recipient. A sender that looks the agent up by ID could seal files to the wrong host, against [ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md).
- **The workspace** never reaches the host, so nothing checks it. A compromised orchestrator can list a development host in the production workspace, and the administrator signs that.

The fingerprint check works, but it covers only the keys and the name.

## Decision

ADR 0018's decisions stay, with these changes.

**Agent IDs come from the keys.** An agent's ID is the first 16 bytes of its agent fingerprint, formatted as a version 8 UUID ([RFC 9562](https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-8)), which leaves 122 bits of the digest. The host computes it when it generates its keys, and puts it in the enrollment request and its proof. The orchestrator stores the agent under that ID and refuses a request whose ID doesn't match its keys. The orchestrator can no longer choose the ID, and no two key sets can share one.

**Every verifier checks the ID.** An identity statement records the fingerprint its ID was derived from, as `enrollment_fingerprint`. Every verifier requires the ID to match that fingerprint. Until key rotation exists, the enrollment fingerprint must also equal the fingerprint of the keys in the statement. So an identity that pairs an ID with other keys is refused everywhere, even if an administrator signed it by mistake.

**The workspace comes from the host.** `mmft-agent install` takes `--workspace`, which `mmft agent token` already prints, and binds it in the enrollment proof. The orchestrator refuses a request whose workspace differs from the token's. The host saves the workspace and reports it in `mmft-agent fingerprint`. `mmft agent approve` signs only when the workspace also matches. An agent refuses an identity for any other workspace.

**The enrollment proof** holds the token hash, the agent ID, the workspace, the agent name, all three public keys, and the CSR hash. It is checked as ADR 0018 describes.

**The agent fingerprint** is unchanged: the hex SHA-256 of a version tag, the Ed25519 key, the ML-DSA-65 key, and the encryption recipient with a decimal length prefix.

**`mmft agent approve`** compares the workspace, agent ID, agent name, and fingerprint with the values from the host, and signs only on an exact match. It also checks agents the orchestrator reports as already approved. If such an agent doesn't match, it is reported as a mismatch, not as already approved.

## Alternatives considered

- **Random agent IDs chosen by the host:** the orchestrator can't choose them, but a compromised host can claim an existing agent's ID. Only a record of every signed ID would catch that, and a deployment pipeline has nowhere reliable to keep one.
- **A record of signed IDs on the administrator's machine:** it catches duplicates only for one approver on one machine. Automation keys and several administrators would each need the same shared record.
- **Leaving the ID to the orchestrator, and having senders check fingerprints:** every sender would need a fingerprint from outside the orchestrator for every destination, which is the problem identities exist to solve.
- **Using the full fingerprint as the ID:** stronger, with 128-bit collision resistance and 256-bit second-preimage resistance. But agent IDs would stop being UUIDs, which the schema, the connection certificates, and the API all use.

## Consequences

Keeping 122 bits of the fingerprint costs strength. Taking another agent's ID means finding keys whose fingerprint starts with that agent's 122 bits, a second preimage, at about 2^122 work. That's the attack this ADR closes, and it stays out of reach. Making any two key sets share an ID is a collision, at about 2^61 hash work, and every attempt also costs a key generation. An attacker who managed it would hold both key sets, so it would harm no other agent. Each identity also records the full fingerprint, which still tells the two apart in audit evidence. If a collision ever becomes a practical concern, the ID scheme can move to the full fingerprint in a new ADR.

The orchestrator can no longer choose any value an administrator signs. A compromised orchestrator can still withhold or delay approvals, as before.

Agents enrolled before this change have IDs the orchestrator chose, so they must enroll again. No release includes agent enrollment yet, so this affects only the lab and test data.

An agent ID now changes if an agent enrolls again with new keys. Key rotation must keep the ID. It will do so by carrying the original enrollment fingerprint and having the old keys sign for the new ones. That design, and the exception it needs to the equal-fingerprints rule above, belong to the ADR for `mmft agent renew` with key changes.

The workspace is now part of the install command. That keeps the deployment tool, not the orchestrator, as the source of what each host is for.
