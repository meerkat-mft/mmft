# 0022. Flow version format

Status: Accepted
Date: 2026-11-07

Refines [ADR 0006](0006-flows-are-card-trees.md) and [ADR 0012](0012-signed-statements-and-flow-approval.md).

## Context

ADR 0006 makes a flow a tree of cards stored as signed, versioned JSON. ADR 0012 says what the signed payload must hold: the flow's identity, its workspace, an increasing version number, and the agents it names. M2 is the first time flow versions are signed and run, so the payload needs an exact format. Once administrators have approved flow versions, changing the format means new payload versions that every agent must read, so the choices are hard to reverse.

The payload is also what an administrator reviews in `mmft flow approve`. Anything that two readers could take differently, or that hides what the flow does, weakens that approval.

## Decision

The payload of `application/vnd.mmft.flow-version+json;v=1` is one JSON object:

```json
{
  "version": 1,
  "flow_id": "0190f9c3-2b7d-7e01-8000-0000000000f1",
  "workspace": "finance",
  "flow_version": 4,
  "agents": ["…-a", "…-b"],
  "cards": [
    { "id": "pickup", "type": "source", "agent": "…-a", "path": "/srv/outbox" },
    { "id": "ledger", "type": "destination", "parent": "pickup", "agent": "…-b", "path": "/srv/inbox" }
  ]
}
```

- **Cards are a flat list, and each card names its parent.** A card has at most one parent, so a join can't be written. Validation rejects the rest of what isn't a tree: loops, a missing or second root, and unknown parents.
- **Card IDs are short, stable names,** unique within a version (`^[a-z][a-z0-9-]{0,31}$`), so a diff between two versions lines up card by card.
- **Version 1 has two card types.** The `source` card is the root, and each `destination` card follows it directly, on another agent. There must be at least one destination, and no two can name the same agent and path. Conditions, selection rules, triggers, outcomes, and failure branches will be new card types in a new payload version, which version 1 agents refuse. The `parent` shape already allows the deeper trees they need.
- **Cards name agents by agent ID.** Names can change, and a signature must bind to an identity. The CLI shows names next to the IDs.
- **`agents` repeats the agents the cards name,** sorted and without repeats, and must match them exactly. An agent can then see whether it takes part before reading the cards.
- **A path has one canonical form.** It must be absolute: a POSIX path, or a Windows path on an upper-case drive. It can't have empty, `.`, or `..` segments, or a trailing separator. On Windows, it can't have names that Windows would read differently, such as a trailing dot or space. It can't contain control characters, line breaks, or the marks that reorder text. Its limit is 1,024 bytes. The administrator approves exactly the path that runs. The agent still resolves links and checks the path against its allowlist ([ADR 0013](0013-agent-allowlists.md)).
- **Decoding is strict at every depth.** Field names are lower-case ASCII and appear once in each object. There are no unknown fields, no nulls, no trailing data, and no nesting beyond what the format uses.
- **The flow's name, the canvas layout, and who approved are not signed.** Renaming a flow or moving a card needs no new approval. The orchestrator stores them alongside the version, and the statement's signatures already say who approved.
- **The signed bytes are the bytes that were checked.** The orchestrator builds the payload from a draft. The CLI checks those exact bytes, shows the difference, and signs them unchanged. Nothing is re-encoded between review and signature.

The Go package `internal/flow` is the authority on this format, and the API, the CLI, and the agent all use it. `api/flow-version.schema.json` documents the format as a JSON Schema, and `scripts/check-api.sh` keeps it in step with the package's fixtures. Rules a schema can't express, such as the tree's shape and fields that must agree with each other, are checked only by the package.

## Alternatives considered

- **Nested cards, each holding its children:** a loop or join can't be written at all. But diffs follow the nesting rather than the cards, every new card type must nest, and the canvas's flat model has to be converted both ways.
- **Cards that list their children (`next`):** a join can be written, and validation would have to refuse it. With `parent` it can't be written.
- **Agents named by name:** easier to read in the payload, but a renamed or re-enrolled agent would silently change what an approval means.
- **Paths kept as written:** simpler, but `/srv/outbox/../../etc` and `/srv/outbox` could look alike to a reviewer and mean different things. The allowlist would still stop the worst cases, but the approval would no longer show what runs.
- **Signing the name and layout:** the approver would see them in the signed bytes, but cosmetic changes would need new approvals, which teaches administrators to approve without reading.
- **No `agents` list:** smaller, but every agent would have to parse and validate all the cards to learn whether a flow concerns it.

## Consequences

- An approved flow version means exactly one thing to the API, the CLI, and every agent. A flow version the API stored can't be read differently by an agent.
- Version 1 flows are shallow: one source and its destinations. Branching by condition needs payload version 2, and agents must be updated before such flows can run.
- A source and a destination can't be on the same agent, because a delivery always moves between two agents. A local copy would need its own design.
- Windows UNC paths aren't accepted yet. They need their own canonical form, and will come with the Windows work.
- Revisit this if a later card type can't be expressed as one parent per card.
