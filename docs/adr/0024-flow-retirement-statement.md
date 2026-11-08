# 0024. Flow retirement statement

Status: Accepted
Date: 2026-11-08

Refines [ADR 0012](0012-signed-statements-and-flow-approval.md).

## Context

ADR 0012 says a signed retirement statement stops a flow permanently, and that only an administrator key may sign one, but it gives the statement no format. Agents will keep every retirement they accept and refuse the flow for ever after, so the format is hard to change once retirements exist.

## Decision

The payload of `application/vnd.mmft.flow-retirement+json;v=1` is:

```json
{ "version": 1, "flow_id": "0190f9c3-2b7d-7e01-8000-0000000000f1", "workspace": "finance" }
```

- **It names only the flow and its workspace.** A retirement stops every version of the flow, past and future, so it names no version. Naming the workspace binds it to the flow's place, as the flow version payload does.
- **The administrator states the workspace.** `mmft flow retire --workspace NAME` refuses if the orchestrator reports the flow in another workspace, so the signed payload says what the administrator meant, not what the orchestrator claimed.
- **It travels and is stored like an approval** ([ADR 0023](0023-approvals-carry-their-certificates.md)): the statement with its signers' certificates and the root key. The orchestrator stores it only if it verifies against them and names this flow and its workspace. Agents check it against their pinned root.
- **It is decoded with the same strict rules as a flow version** ([ADR 0022](0022-flow-version-format.md)), by `flow.ParseRetirement`.
- **A retired flow takes no new drafts or approvals.** Its versions and runs stay, as evidence.

## Alternatives considered

- **Retire one version at a time:** finer grained, but an approved version can already be replaced by approving a newer one, and an attacker could still run an older version unless every one was retired. Stopping the whole flow is the clear, safe meaning.
- **Mark the flow retired in the orchestrator only:** simpler, but a compromised orchestrator could quietly un-retire a flow. Agents need something signed to refuse it on their own.
- **Include a reason or a time:** useful to read, but the audit trail records who retired the flow and when, and free text would be signed for ever.

## Consequences

- Retiring a flow can't be undone. Running the same work again needs a new flow, with a new ID.
- Any retirement of a flow is the same statement, because its payload depends only on the flow and its workspace ([ADR 0015](0015-strict-signed-statement-profile.md)). Retiring again changes nothing.
- Agents enforce retirement in #78.
