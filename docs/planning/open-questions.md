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
- **Project accounts.** Claim `meerkat-mft` on GitHub and Docker Hub, because `mmft` is already taken on both. Reserve `mmft` on npm and PyPI if the release plan needs them.
- **Go module domain.** Make mmft.dev answer over HTTPS and serve the `go-import` tag that Go tooling needs for `mmft.dev/mmft`. It timed out on 2026-10-31.

## When the repo goes public

- **Merge protection.** Require CI to pass on `main`. GitHub's free plan does not offer this for private repos, so until then it is a manual rule.
- **Vulnerability reports.** Turn on private vulnerability reporting.

## M1 and M2

- **Relay limits.** What are the bandwidth, concurrency, and per-agent limits?
- **Audit buffer size.** How much can an offline agent hold before it stops new work?
- **Windows agent.** How does it run as a service, and how does safe placement work on Windows?

## M3

- **Design language.** Before building the console, write a one-page brief, prototype three directions on the flow canvas, a partial failure run, and a delivery's audit trail, then extract tokens from the chosen one. Settle how brand amber differs from warning states, and include dark mode from the start.

## Before any sale

- **Cyber Resilience Act.** Verify the dates and whether Meerkat counts as a manufactured product, with legal advice.
- **Trademark.** Search "Meerkat" and "Meerkat MFT" in Nice classes 9 and 42 on the EUIPO and BOIP registers before spending on branding. Web searches found US MEERKAT marks in security software, but the EU registers have not been checked.
- **Contributor agreement.** Choose one before accepting outside code.
