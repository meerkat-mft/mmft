# 0021. Manual deliveries in M1

Status: Accepted
Date: 2026-11-06

## Context

M1 must move a file between two agents through the relay, with the orchestrator unable to read it. That is the first code that reads and writes customer files. Flows, signed flow versions, and the agent allowlists of [ADR 0013](0013-agent-allowlists.md) arrive in M2, so M1 has nothing yet to limit what an agent may read or write. Without a limit, a compromised orchestrator could have an agent seal any file it can open, or write anywhere it can.

## Decision

**A manual run.** `POST /api/v1/runs`, with `mmft delivery send` in the CLI, starts a run with no flow and one delivery. Its file goes from the source agent's outbox to the destination agent's inbox. The two agents must be approved, in the same workspace, and connected. Otherwise the API refuses the run and creates nothing. There are no retries or leases. If an assignment can't reach an agent, because its stream ended first, the run is created and fails with `dispatch_failed`.

**An outbox and inbox.** Each agent takes deliveries only through two directories set on its host, `mmft-agent run --outbox DIR --inbox DIR --spool DIR`. The orchestrator can't change them. An agent without them takes no deliveries. The three directories must be different. A delivery names a bare file name, never a path: 1 to 255 bytes of valid UTF-8, with no separator, colon, NUL, or control character, not `.` or `..`, not ending in a dot or space, and not a Windows device name. The rule holds on every platform, so a name can only ever mean one file in the directory. The source reads it from its outbox only if it is a regular file that isn't a link, and the destination creates it in its inbox. The allowlist in M2 replaces this.

**Each agent checks the other itself.** The orchestrator sends each agent the other's identity statement over its stream. The agent verifies it against its own pinned root, and requires it to name the expected agent in its own workspace. The source seals only to a recipient verified this way, and the destination accepts only a manifest signed by the verified source. So a compromised orchestrator can't substitute keys on either side.

**Steps.**

1. The orchestrator sends the source a `ManualDelivery` with a send ticket.
2. The source seals the file into its spool, sends the signed manifest in a `DeliveryUpdate`, and sends the sealed file through the relay.
3. The orchestrator stores the manifest, and sends the destination a `ManualDelivery` with the manifest and a receive ticket.
4. The destination checks that its spool and inbox each have room for the manifest's size. It receives at most that size, and checks the hash before decrypting, as [ADR 0010](0010-age-sealed-files.md) requires.
5. The destination places the file with a hard link, which fails rather than replace anything, including a planted link. It then sends a signed delivery receipt.
6. The orchestrator marks the delivery `succeeded` and `verified` only with both statements, as [ADR 0014](0014-audit-batches-and-delivery-receipts.md) requires.
7. Both agents delete their spooled copies.

A failure on either side is reported as a stable error code, never as a path or raw error output.

**Bounds on each agent.** An agent runs at most 8 deliveries at once and refuses more with `agent_busy`, and it never runs the same delivery twice at the same time. So a compromised orchestrator can't make it fill its spool with copies or hold unbounded relay streams.

**Updates from the wrong agent are ignored.** An update for a delivery an agent isn't part of, or for the wrong side, changes nothing, so no agent can end another pair's delivery.

**A test tap on the relay.** `relay.Config.Tap` lets a program see each forwarded message. Only `lab/mmft-testrelay` sets it, to check in the lab that the relay sees only the sealed file. `mmft-relay` never sets it.

## Alternatives considered

- **A first cut of the ADR 0013 allowlist now:** closer to the end state, but it pulls M2 work into M1, and the allowlist file format is better settled together with signed flows.
- **Paths chosen in the API:** most flexible, but a compromised orchestrator could then read or write anything the agent's account can.
- **Trusting the orchestrator's view of each agent's keys:** simpler, but it gives a compromised orchestrator the power to read files, which ADR 0002 rules out.
- **Replacing an existing destination file:** expected by some tools, but it can destroy data, and a planted link could redirect the write.
- **Checking only the source's sealed file for plaintext:** needs no test relay, but it doesn't show what the relay actually forwards.

## Consequences

- Moving a file takes host access to put it in the outbox. That is acceptable for M1, which proves the path, not the workflow.
- Deliveries to an agent that is offline are refused rather than queued until M2's state machine.
- A delivery that fails after its manifest leaves the other side to time out at the relay.
- An agent that goes silent mid-delivery leaves the run `running` until M2's leases end it.
- Error codes the agent reports become part of the API's contract.
- When the allowlist arrives, the outbox and inbox flags are replaced, and a new ADR records how.
