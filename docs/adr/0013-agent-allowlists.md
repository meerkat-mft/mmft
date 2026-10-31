# 0013. Agent allowlists are local files managed on the host

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0003](0003-trust-root-allowlists-signed-flows.md) requires a local agent allowlist that the orchestrator can't change. It is the last defense when an orchestrator or administrator key is compromised. Threat model finding F6 requires that a compromised agent process can't widen its own allowlist.

## Decision

Each agent reads one allowlist file, at `/etc/mmft/allowlist.yaml` on Linux and in the Meerkat MFT configuration folder on Windows. The file is owned by root or Administrators, and the agent's service account can read it but not change it. The agent runs as a dedicated, unprivileged account.

The file lists:

- Paths the agent may read.
- Paths the agent may write.
- Agents it may send to or receive from, by name or by workspace.
- How many administrators must approve a flow.
- Later, remote endpoints it may reach.

The default is empty, and an empty allowlist denies everything. Changing it requires access to the host, normally through the customer's deployment tool, so it fits the same unattended rollout as enrollment. No remote command changes it.

Every computed path is made absolute and has its links resolved before it's checked, and files are opened in a way that refuses a swapped link. A flow that breaks the allowlist fails with a clear reason, and is not partly run. The agent reports the hash of its allowlist, and each change is recorded as an audit event.

## Alternatives considered

- **Allowlists signed by an administrator and delivered by the orchestrator:** easier to manage, but a stolen administrator key would then defeat the last defense.
- **Signed by the trust root:** safer, but it brings the root online for routine work.
- **No allowlist, relying on flow signing alone:** simpler, but one stolen administrator key could send anything anywhere.

## Consequences

A compromised orchestrator or administrator key can't reach paths or agents outside the allowlist. Adding a new path to a flow means a change on the host as well as an approval, which is deliberate friction and needs clear errors. A deployment tool can manage these files at scale. A user with root access to the host can still change the file, which the threat model places out of scope.
