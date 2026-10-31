# M0 tasks

M0 is done when the design is written down and CI passes. Do these in order. Hours are rough estimates.

## Set up the project

- [x] **1. Create the repo (1 hour).** Create the `meerkat-mft` GitHub organization, require 2FA, and push a private `mmft` repo.
- [x] **2. Add project files (2 hours).** Add the AGPL `LICENSE`, `README.md`, `CHANGELOG.md`, and `SECURITY.md` with how to report a vulnerability.
- [x] **3. Set up Go (2 hours).** Install Go, initialize the `mmft.dev/mmft` module, and add empty `mmft`, `mmft-orchestrator`, `mmft-relay`, and `mmft-agent` commands under `cmd/`.
- [ ] **4. Add CI (4 hours).** Run build, tests, linting, `govulncheck`, and SBOM generation on every push, add automated dependency pull requests, and require CI to pass before merging. Confirm the release tooling, likely GoReleaser and Cosign, so that signed releases can start in M1.
- [ ] **5. Point the Go module at the repo (1 hour).** Make mmft.dev answer over HTTPS and serve the `go-import` tag.

## Settle the design

- [ ] **6. Write the threat model (6 hours).** Write `docs/threat-model.md`, covering a compromised orchestrator, relay, agent, and administrator account.
- [ ] **7. Choose the encryption format (4 hours).** Write an ADR for end-to-end encryption, including chunking for resume.
- [ ] **8. Design trust root operation (5 hours).** Write an ADR for generating, storing, using, and recovering the trust root, including the agent signing step.
- [ ] **9. Design flow signing and allowlists (4 hours).** Write an ADR for how administrators sign flows from a browser and an API client, and for the allowlist format.
- [ ] **10. Sketch the interfaces (5 hours).** Draft the OpenAPI spec and agent gRPC definitions for M1 and M2.

## Prepare for M1

- [ ] **11. Set up the lab (3 hours).** Build two VMs and write the failure test plan covering killed processes, dropped networks, full disks, and expired certificates.

## Done when

- CI passes on an empty but buildable project.
- The threat model and all three ADRs are accepted.
- The M1 interfaces are drafted, and the lab can run them.
