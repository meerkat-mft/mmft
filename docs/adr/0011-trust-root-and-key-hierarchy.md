# 0011. Trust root operation and key hierarchy

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0003](0003-trust-root-allowlists-signed-flows.md) requires an offline, customer-held trust root that the orchestrator never holds. Threat model finding F10 asks how keys are used day to day without bringing the root online, and how a customer recovers if the root is lost. No hardware key was confirmed to support ML-DSA signing, so the design can't depend on one.

## Decision

### Key hierarchy

| Key | Held by | Signs | Lifetime |
| --- | --- | --- | --- |
| **Trust root** | Customer, offline | Administrator keys, revocations, root rollover | Until rolled over |
| **Administrator key** | One administrator's CLI | Flow approvals, agent identities, automation keys | 1 year |
| **Automation key** | One deployment pipeline | Agent identities only, within one workspace | 90 days |
| **Agent identity** | One agent | Delivery manifests, audit batches | 1 year |
| **Agent encryption key** | One agent | Nothing. Opens sealed files and credentials | Same as its identity |
| **Connection certificate** | Agent, relay, orchestrator | mTLS sessions, issued automatically by the orchestrator | 24 hours |

Trust root, administrator, automation, and agent keys sign with both Ed25519 and ML-DSA-65, and both signatures are required. Connection certificates stay classical, with hybrid key exchange. They prove only who may connect, so a compromised orchestrator gains nothing beyond its existing position by forging one. End-to-end trust always comes from the chain to the trust root.

### Trust root

`mmft trust init` generates the root on an administrator's machine and writes it to a passphrase-encrypted file that is kept offline. The customer keeps at least two copies, with the passphrase stored separately. The CLI pins the root's fingerprint and refuses to run the signing steps without it. Normal operation never needs the root. It's used only to add or revoke an administrator key or to roll over the root.

### Enrollment

1. An administrator runs `mmft agent token`, which prints an install command with a one-use token that expires in one hour, and the root fingerprint.
2. The agent is installed with that command, pins the fingerprint, generates its keys locally, and prints a short key fingerprint on the host.
3. The administrator runs `mmft agent approve`, compares the fingerprint with the one on the host, and signs the agent identity.
4. The agent verifies the chain to the pinned root and starts accepting work.

Comparing fingerprints stops a compromised orchestrator from swapping an agent's keys during enrollment.

### Unattended rollout

Every step must run from a script, such as Ansible, DSC, Bash, or PowerShell, with no prompts, stable exit codes, JSON output, and safe repeat runs. The fingerprint comparison stays, but the deployment tool performs it:

1. The pipeline runs `mmft agent token` for each host.
2. It installs the agent on each host over its own channel, such as SSH or WinRM.
3. It collects each fingerprint from the host with `mmft-agent fingerprint --json`.
4. It runs `mmft agent approve --fingerprints <file>` on its controller, which signs only agents whose fingerprints match.

Fingerprints travel through the customer's deployment channel, never through the orchestrator, so the protection holds. The pipeline signs with an **automation key**, which an administrator key issues. It can sign and renew agent identities in one workspace, and it cannot approve flows or sign for another workspace. A stolen automation key can add agents, but they receive no work until an approved flow names them.

### Rotation and revocation

- Agent identities are renewed in bulk with `mmft agent renew`, which can run on a schedule with an automation key. Renewal keeps the agent's existing keys. Changing keys needs a new fingerprint check. An expired identity stops working.
- Revocations are signed by the trust root for administrator keys, or by an administrator key for automation keys and agent identities, and carry a version number that agents never accept going backwards.
- The orchestrator distributes revocations, and could withhold them if compromised. `mmft-agent trust revoke` applies one directly on a host, and allowlists still limit the damage in the meantime.
- A root rollover signed by the old root updates agents automatically.

### Recovery

- **Lost administrator key:** another administrator key can't replace it. The trust root issues a new one.
- **Lost trust root:** existing keys keep working until they expire, which gives the customer up to a year to move. A new root requires `mmft-agent trust repin` on every host, which the deployment tool can run. There is no recovery service and no vendor copy.
- **Compromised trust root:** the customer creates a new root and enrolls every agent again.

## Alternatives considered

- **A signing service beside the orchestrator:** enrollment is smoother, but an always-online key on the same infrastructure brings back the risk ADR 0003 removes.
- **Self-service agent renewal:** no pipeline step, but a stolen agent key could then renew itself forever.
- **Generating agent keys in the pipeline:** simple to script, but private keys would leave the host and sit in deployment tooling.
- **Trusting the first agent to use a token:** the simplest rollout, but a compromised orchestrator could swap keys, because nothing checks them independently.
- **Hardware-only root:** the strongest storage, but it isn't possible for ML-DSA yet. Hardware can be added later.
- **Vendor-held key escrow:** it makes recovery easy, but it gives Meerkat's maintainers a master key, against the product's main promise.
- **Splitting the root into shares:** useful for larger organizations, but it adds complexity and tooling the MVP doesn't need.
- **X.509 chains for identities:** familiar, but hybrid signatures aren't settled there, so we'd run two parallel chains.

## Consequences

The orchestrator has no key that can create an agent identity or approve a flow. Enrollment and renewal can be fully automated, but the customer must protect the automation key in their pipeline, and an administrator must reissue it every 90 days. Losing the root is painful by design, because no one else can restore it. Customers must look after the offline file, so setup should make this hard to skip, and the documentation needs a tested recovery runbook.

Identities use Meerkat's own signed statements rather than X.509. They use standard primitives, but the protocol around them is ours, so it needs external review before any regulated customer relies on it. The statement format is settled in [#8](https://github.com/meerkat-mft/mmft/issues/8).
