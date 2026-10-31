# Open questions

The product questions are answered in the [PRD](prd.md) and the [ADRs](../adr/). These remain. Settle each in the milestone shown, and write an ADR if it is expensive to reverse.

## M0: Foundations

- **Threat model.** Write it, starting from a compromised orchestrator, relay, agent, and administrator account.
- **Encryption format.** Choose the audited format or library for end-to-end encryption, including how large files are chunked for resume.
- **Trust root operation.** How is it generated, stored, and used, and how does a customer recover from losing it?
- **Agent signing step.** What exactly does an administrator do at enrollment, and how are signing keys below the root protected?
- **Flow signing.** How does an administrator's signature work from a browser and from an API client?
- **Agent allowlist format.** Where does it live, and how is it changed on the system itself?
- **Toolchain.** Install Go on this machine, and choose the CI provider.

## M1 and M2

- **Relay limits.** What are the bandwidth, concurrency, and per-agent limits?
- **Audit buffer size.** How much can an offline agent hold before it stops new work?
- **Windows agent.** How does it run as a service, and how does safe placement work on Windows?

## Before any sale

- **Cyber Resilience Act.** Verify the dates and whether Meerkat counts as a manufactured product, with legal advice.
- **Trademark.** Search "Meerkat" in software before spending on branding.
- **Contributor agreement.** Choose one before accepting outside code.
