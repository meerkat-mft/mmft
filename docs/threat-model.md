# Threat model

Status: Draft for review, 2026-10-31. Terms follow [GLOSSARY.md](../GLOSSARY.md).

This model covers the MVP design and the roadmap items that change it. It starts from a compromised component and asks what the attacker gets. Findings at the end feed the M0 design ADRs.

## What we protect

| Asset | Why it matters |
| --- | --- |
| File contents | The main thing customers trust us with |
| Endpoint credentials | They open systems beyond Meerkat |
| Metadata | File names, partners, and schedules can be personal or sensitive |
| Audit evidence | It is worthless if it can be altered unnoticed |
| Flow definitions | They decide where files go |
| Trust root and signing keys | They anchor every other guarantee |
| Availability of deliveries | Customers depend on files arriving on time |

## Trust boundaries

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Orchestrator | Scheduling, coordination, record keeping | File contents, credentials, deciding what an agent may access |
| Relay | Forwarding bytes | Confidentiality, integrity, or truth about a delivery |
| Agent | Files and credentials on its own system | Anything on other systems, or the truth of its own reports without a second check |
| Console in a browser | Drafting flows and showing state | Flow approval and credential entry, which happen in the signed CLI |
| Database and backups | Durable storage | Confidentiality of secrets, or integrity of signed data |
| Administrator | Their role's actions | Being uncompromised |
| Trust root holder | All of the above | Must stay offline |

## Compromise scenarios

### Compromised orchestrator

**Designed outcome:** the attacker cannot read file contents or credentials, and cannot send files outside agent allowlists.

**The attacker still can:**
- Read all metadata.
- Stop all work.
- Trigger valid flows at the wrong time, or repeat them.
- Replay an older signed flow version (F2).
- Corrupt audit records made since the last audit checkpoint.
- Show false state to administrators, or get them to approve a flow based on it. The CLI shows the real change (F1).
- Withhold or swap public keys, unless agents verify them against the trust root.

### Compromised relay

**Designed outcome:** the attacker sees only ciphertext.

**The attacker still can:**
- See who talks to whom, when, and how much.
- Drop, delay, reorder, or replay data (F3).
- Stop all agent-to-agent delivery.

### Compromised agent

**Designed outcome:** damage is limited to that system and the flows it takes part in.

**The attacker gets:**
- Every file that agent can read or that passes through it.
- Credentials sealed to that agent.

**The attacker can also:**
- Report false results. A source agent can lie about a checksum, and a destination agent can claim receipt (F4).
- Attack the orchestrator with hostile metadata, such as file names built to break the console or logs (F5).
- Edit its own allowlist if the agent's OS user can write to it (F6).

A root-level compromise of the host is out of scope for prevention. Limiting the blast radius to that host is the goal.

### Compromised administrator account

**Designed outcome:** agent allowlists still limit where files can go, and actions are recorded.

**The attacker can:**
- Change flows between allowed paths and destinations, if they can also sign (F7).
- Disrupt work, delete configuration, and add users.
- Phish a TOTP code, because TOTP does not resist phishing (F8).
- Mint API tokens that outlive the session (F8).

### Stolen database or backup

**Designed outcome:** no file contents and no readable endpoint credentials.

**The attacker gets:** all metadata, plus whatever auth data is stored. TOTP secrets, API tokens, and session data must not be usable from a copy (F9).

**With write access, the attacker can:** alter flows, which agents must reject because signatures fail, and alter audit records, which verification against audit checkpoints must catch.

### Compromised trust root or signing keys

- **Trust root:** total loss of the design's guarantees. An attacker can enroll rogue agents and read relayed files.
- **Lost trust root:** every agent must be enrolled again unless recovery is designed (F10).
- **Key used to sign agents:** if it lives on the orchestrator, ADR 0003's guarantee fails (F10).

### Supply chain

Anything that can push to `meerkat-mft/mmft` can reach every future install. That covers the maintainer's `gh` login, the Claude GitHub App, CI workflows, and dependencies. `main` has no enforced protection while the repo is private on the free plan (F11).

**Agent updates:** the orchestrator can start an update but cannot sign one. It could still offer an older, vulnerable signed release (F2).

## Abuse of normal features

| Feature | Risk | Required control |
| --- | --- | --- |
| Destination path templates | Path traversal from hostile file names | Canonicalize the path, then check the allowlist |
| Local files connector | Symlink swaps between check and use | Open files safely, and refuse to follow links by default |
| CEL rules | Expensive expressions used for denial of service | Enforce cost limits, and validate on the server |
| Enrollment tokens | Theft of a token enrolls a rogue agent | One use, short expiry, and an administrator signing step |
| Webhooks | Metadata leaks, or requests to internal addresses | Administrator-only setup, and block internal targets by default |
| Audit export | A sensitive copy of metadata leaves the system | Treat exports as sensitive, and record them |
| Certificates | Expiry stops all work | Automatic renewal, and alerts before expiry |

## Findings

Priority: **Blocker** must be solved in the M0 design. **Required** must be built by the milestone shown.

| ID | Finding | Priority | Goes to |
| --- | --- | --- | --- |
| F1 | **Console trust.** Code served to a browser can be altered by whoever serves it, which could capture credentials and misdirect signing. Resolved by [ADR 0009](adr/0009-trusted-approvals-in-the-cli.md): approval and credential entry move to the signed CLI, and the console is a separate container. | Resolved | ADR 0009 |
| F2 | **Replay and rollback.** A signature alone doesn't stop an older signed flow version or agent release from being reused. Agents need to track the newest version they have accepted, and flow versions should be revocable. | Blocker | [#8](https://github.com/meerkat-mft/mmft/issues/8) |
| F3 | **Relay tampering.** Encryption must bind every chunk to its delivery, position, and total, so that reordering, truncation, and replay all fail. | Blocker | [#6](https://github.com/meerkat-mft/mmft/issues/6) |
| F4 | **Self-reported evidence.** Audit events from one agent prove only what that agent claims. A delivery record should need signed statements from both agents, with the destination's checksum computed independently. | Required, M2 | [#8](https://github.com/meerkat-mft/mmft/issues/8) |
| F5 | **Hostile metadata.** Everything an agent reports is untrusted input to the orchestrator and console. Validate it on the server, escape it in the console, and set a strict content security policy. | Required, M3 | [#9](https://github.com/meerkat-mft/mmft/issues/9) |
| F6 | **Allowlist protection.** The agent's OS user must not be able to write its own allowlist or configuration. Each agent needs least-privilege packaging on Linux and Windows. | Required, M2 | [#8](https://github.com/meerkat-mft/mmft/issues/8) |
| F7 | **One administrator can do everything.** In the MVP, one stolen administrator identity can change and sign a flow. Four-eyes approval is on the roadmap, so the signing design must allow a second signature later. | Blocker for the design | [#8](https://github.com/meerkat-mft/mmft/issues/8) |
| F8 | **TOTP and API tokens.** TOTP can be phished, and long-lived tokens outlast a session. Passkeys are on the roadmap. Keep tokens scoped, expiring, and revocable. | Required, M3 | [#24](https://github.com/meerkat-mft/mmft/issues/24) |
| F9 | **Auth data at rest.** Hash API tokens, encrypt TOTP secrets with a key held outside the database, and include backups in this rule. | Required, M3 | [#25](https://github.com/meerkat-mft/mmft/issues/25) |
| F10 | **Key hierarchy and recovery.** The design needs an online-usable agent signing key that isn't on the orchestrator, with rotation, and a tested recovery path for a lost trust root. | Blocker | [#7](https://github.com/meerkat-mft/mmft/issues/7) |
| F11 | **Repo protection.** Enforce protected `main` and required reviews before anyone depends on a release, and keep the GitHub App limited to selected repos. | Required, M1 | [#16](https://github.com/meerkat-mft/mmft/issues/16) |
| F12 | **"Nothing needs to face the internet" has limits.** Agents outside the customer's network must reach the orchestrator and relay somehow. Agents on other networks need a private link, or those services become exposed. Document supported topologies, and treat the public claim as depending on them. | Required, M1 | [#9](https://github.com/meerkat-mft/mmft/issues/9) |
| F13 | **Metadata exposure.** A compromised orchestrator reveals file names and partners. File name masking is on the roadmap, and sensitive customers need to be told this plainly. | Accepted for the MVP | Roadmap |
| F14 | **Traffic analysis at the relay.** Sizes and timing stay visible. | Accepted for the MVP | None |
| F15 | **Single maintainer security response.** One person can't guarantee fast fixes. `SECURITY.md` says so. | Accepted until 1.0 | None |

## Out of scope

- Root compromise of a customer host, beyond limiting it to that host.
- The security of partner systems and customer-owned endpoints.
- Physical attacks on customer infrastructure.
- A customer's own administrators acting with valid authority, beyond recording what they do.

## Keeping this current

Review this model when an ADR changes a trust boundary, when a connector or the bundled agent ships, and before each release from 0.5 onwards.
