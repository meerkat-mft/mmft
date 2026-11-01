# Meerkat MFT

Meerkat MFT (`mmft`, domain mmft.dev) is a managed file transfer (MFT) platform. The design is agreed, and application code is starting.

## Current phase

M1: Skeleton. Work is tracked in [GitHub issues](https://github.com/meerkat-mft/mmft/issues), milestones, and the [Project board](https://github.com/orgs/meerkat-mft/projects/1). Work through the M1 milestone in dependency order, keeping to the milestone's scope. Flow signing, allowlists, and the state machine come in M2.

## Where things live

- [GLOSSARY.md](GLOSSARY.md): domain glossary. Use these terms exactly in docs, code, and conversation. Add or correct a term here when its meaning is settled.
- [docs/naming.md](docs/naming.md): names for binaries, services, paths, config, APIs, and CLI commands.
- [docs/conventions.md](docs/conventions.md): versioning, upgrades, work tracking, the website, git workflow, releases, support, and dependencies. Follow these rules.
- [docs/deployment.md](docs/deployment.md): supported network topologies and handling of untrusted metadata.
- [api/](api/): draft OpenAPI spec and agent and relay protobuf definitions. Run `scripts/check-api.sh --write` after changing them. Generated code is in `gen/`, which must not be edited by hand.
- [docs/data-model.md](docs/data-model.md): what the orchestrator stores and why. Update it with every schema change.
- [docs/adr/](docs/adr/): architecture decisions. One file per decision, copied from `0000-template.md` and numbered in sequence.
- [docs/planning/prd.md](docs/planning/prd.md): product scope, the MVP, and milestones.
- [docs/planning/roadmap.md](docs/planning/roadmap.md): stages and releases after the MVP.
- Tasks, bugs, and open decisions live in GitHub issues, not in repo files. Decisions, design, and rules live in repo files.

## Working rules

- Record a decision as an ADR when it is expensive to reverse. When an ADR settles a `decision` issue, link the ADR and close the issue.
- An accepted ADR is changed by writing a new ADR that supersedes it, not by editing it.
- Never commit real credentials, private keys, or customer files, including as test fixtures.
- Never let the orchestrator read file contents or credentials. Any change that weakens this needs a new ADR.
- Every console feature uses the public API.
- Flow approval and credential entry happen only in the signed CLI, never in the console. Any change that weakens this needs a new ADR.
- Never write custom cryptography.
- Follow the issue workflow in the conventions, and keep the Project board up to date.
- All interfaces are dark only. Never add or propose a light theme.
- Public copy names no specific companies or products.
- File names never go in audit events, delivery manifests, or receipts, only in `delivery_files`.
