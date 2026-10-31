# 0009. Flow approval and credential entry happen in the signed CLI

Status: Accepted
Date: 2026-10-31

## Context

[ADR 0002](0002-orchestrator-cannot-read-sensitive-data.md) seals credentials so the orchestrator cannot read them, and [ADR 0003](0003-trust-root-allowlists-signed-flows.md) requires flows signed by an administrator. The [threat model](../threat-model.md) found that both are weaker than they appear if they happen in the console. Code in a browser is only as trustworthy as whoever serves it, so a compromised orchestrator could capture credentials as they are typed, or show one flow while asking an administrator to sign another. Agent allowlists limit misrouted flows, but nothing inside Meerkat limits a stolen credential.

## Decision

The console remains the place to build flows, monitor runs, and manage the system, and it can draft flow versions. Two actions happen only in the signed `mmft` CLI on an administrator's machine:

- **Approving a flow version.** The CLI verifies the previous approved version's signature, shows the change, and signs the new version locally. The console shows the version as waiting for approval.
- **Entering a credential.** The CLI verifies the target agents' keys against the trust root, seals the credential locally, and sends only ciphertext.

The CLI pins the trust root at setup, so it does not depend on the orchestrator to identify agents. The console ships as a separate `mmft-console` container serving static files on its own origin, with a strict content security policy, and the orchestrator does not serve it.

## Alternatives considered

- **Signing in the console:** the smoothest experience, but a compromised orchestrator could control what is signed.
- **A signed desktop console:** strong, but it is a second product to build and update.
- **A companion browser extension:** strong in theory, but it is another product, and enterprises often block extensions.
- **Passkeys or hardware keys alone:** they protect the signing key, but cannot show what is being signed. They can be added to the CLI later.
- **Accepting the risk:** it would weaken the central promise.

## Consequences

The orchestrator cannot alter the tool that approves flows or handles credentials, so the claims in ADRs 0002 and 0003 hold. Publishing a flow takes a step outside the browser, which adds friction, particularly for less technical administrators. Four-eyes approval can use the same command. The separate console container does not protect against a takeover of a shared host, which the CLI step covers. Revisit if a desktop console is ever built.
