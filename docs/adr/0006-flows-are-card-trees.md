# 0006. Flows are trees of cards with declarative rules

Status: Accepted
Date: 2026-10-31

## Context

Administrators want to drag and drop cards onto a canvas, as in Homey Advanced Flow, and need logic to select and route files. Flows must also stay auditable and must not become a way to run code on agents.

## Decision

A flow is a tree of cards stored as signed, versioned JSON, with the canvas as one editor for it. Trees allow branches and failure paths, but no joins or loops. Selection rules and conditions use CEL over file metadata, offered through a rule builder and direct expressions. Files that match no path stay in place and raise an alert. Each path that reaches a destination produces its own delivery, and a run can end in partial failure. The API validates every flow on the server.

## Alternatives considered

- **Linear pipelines:** the simplest, but related logic spreads across flows that can conflict.
- **Route tables:** easy to read, but a less direct fit for the drag-and-drop experience.
- **Full graphs with joins:** flexible, but joins bring hard failure and timeout semantics.
- **Event rules:** flexible, but it is hard to see everything that happens to a file.
- **Mailboxes:** good for decoupling, but they imply Meerkat holds files.
- **Custom scripts:** powerful, but they add code execution on agents.

## Consequences

Each path stays independent, so the run model stays simple and auditors can read a flow directly. Some workflows, such as waiting for two deliveries before sending an acknowledgement, cannot be expressed. Rules cannot inspect contents. Source clean-up waits until every delivery succeeds.
