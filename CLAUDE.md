# Meerkat MFT

Meerkat MFT (`mmft`, domain mmft.dev) is a managed file transfer (MFT) platform. The design is agreed, and application code is starting.

## Current phase

M2: Reliable runs. Work is tracked in [GitHub issues](https://github.com/meerkat-mft/mmft/issues), milestones, and the [Project board](https://github.com/orgs/meerkat-mft/projects/1). Work through the M2 milestone in dependency order, keeping to the milestone's scope. Triggers, selection rules, roles, and the console come in M3. Windows (#3) is on hold. Update this section when a milestone closes.

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
- An accepted ADR is changed by writing a new ADR that supersedes it, not by editing it. The one allowed edit is setting the old ADR's status to `Superseded by NNNN`.
- Never commit real credentials, private keys, or customer files, including as test fixtures.
- Never let the orchestrator read file contents or credentials. Any change that weakens this needs a new ADR.
- Every console feature uses the public API.
- Flow approval and credential entry happen only in the signed CLI, never in the console. Any change that weakens this needs a new ADR.
- Never write custom cryptography.
- Follow the issue workflow in the conventions, and keep the Project board up to date. To work an issue, use the `work-issue` skill.
- All interfaces are dark only. Never add or propose a light theme.
- Public copy names no specific companies or products.
- File names never go in audit events, delivery manifests, or receipts, only in `delivery_files`.

## Git and checks

- Other sessions work in parallel. Before starting an issue or a step, run `git fetch` and check the open and merged pull requests that mention it.
- Stage files by name, never with `git add -A` or `git add .`, and read `git status` before every commit.
- Before pushing to a pull request branch, check that the pull request is still open. Anything pushed after a merge needs a new pull request.
- Run `scripts/check.sh` before pushing. It runs what CI runs and stops at the first failure. Never pipe a check through `tail`, `grep`, or `head`, which hides its exit code.
- Tests that need Postgres skip without `MMFT_TEST_DATABASE_URL`. `scripts/check.sh` starts a throwaway database for them.

## Behavioral guidelines

- Build what the issue asks and no more: no speculative features, configuration, or abstractions for single-use code.
- Touch only what the task needs, and match the existing style. Mention unrelated problems instead of fixing them.
- Remove imports, variables, and functions that your change made unused, but leave pre-existing dead code alone.
- Prove each change with a test. Reproduce a bug in a test before fixing it, and keep tests passing through a refactor.
- Prove a security check with a mutation: break the guarded code, show that a test fails, then restore it.
- When a request has more than one reasonable reading, or a simpler approach exists, say so before building.
