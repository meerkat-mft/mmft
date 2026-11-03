# Project conventions

Rules for versions, releases, and day-to-day development. Names are in [naming.md](naming.md), and release contents are in the [roadmap](planning/roadmap.md).

## Release versions

- All components share one version number and release together: orchestrator, relay, agent, CLI, and console.
- Versions follow Semantic Versioning, such as `0.5.0`, with git tags such as `v0.5.0`.
- Release candidates use `0.5.0-rc.1`.
- During 0.x, a breaking change raises the middle number, and a fix raises the last number.
- From 1.0, a breaking change raises the major version.
- All 0.x releases are beta. The maintainer decides when to release 1.0.

## Interface versions

Each interface has its own version, separate from the release number.

| Interface | How it is versioned |
| --- | --- |
| REST API | The `/api/v1/` path changes only on a breaking change |
| Agent protocol | The orchestrator and agents exchange a protocol version when connecting |
| Flow format | Each flow stores a schema version |
| Audit format | Each record stores its format version, and old evidence stays verifiable |

During 0.x, the REST API can break while staying on `/api/v1/`, if the release notes say so.

## Upgrades

- Agents work with the current orchestrator and the release before it.
- Each release upgrades from the previous release. Skipping versions means stepping through them.
- Database migrations run forward only. Rolling back means restoring a backup.

## Work tracking

- Tasks, bugs, and open decisions are GitHub issues, grouped by milestone. Milestones M0 to M4 match the PRD.
- Issues that are not tied to a milestone use the `before-public` or `before-sale` label.
- Decisions, design, and rules stay in repo files, so they are versioned and reviewed.
- All open issues are on the [Meerkat MFT Project](https://github.com/orgs/meerkat-mft/projects/1), with the status Todo, In Progress, or Done. Add new issues to it when you create them.

### Writing an issue

- Use the issue forms: Task, Bug report, or Decision.
- A task's "Done when" criteria are its spec. The pull request is reviewed against them.
- The maintainer labels an issue `needs-plan` when it is large or risky. Anyone working an issue can suggest the label. Its plan is posted as an issue comment and approved before any code is written.

### Working on an issue

1. Pick an issue from Todo, normally from the current milestone, and set it to In Progress.
2. If the issue is labelled `needs-plan`, post a plan as a comment and wait for approval.
3. Create a short-lived branch from `main`.
4. Open a pull request from the template, with `Closes #n` in its description and a Conventional Commits title.
5. Copilot reviews every pull request automatically. Fix each valid comment and resolve its thread. For a comment that doesn't apply, reply with the reason and leave the thread for the maintainer to resolve.
6. Merge after CI passes and every conversation is resolved, using a squash merge. The branch is deleted automatically.
7. Confirm that the issue is closed and shows as Done.

Claude Code sessions follow these steps through the `work-issue` skill in `.claude/skills/`.

Work that doesn't change the repo, such as DNS or account setup, is closed on the issue once it's verified.

## Website

- mmft.dev is a static site in the public repo [`meerkat-mft/meerkat-mft.github.io`](https://github.com/meerkat-mft/meerkat-mft.github.io), served by GitHub Pages from `main`.
- The site uses no JavaScript, tracking, or third-party requests. Fonts are self-hosted.
- Public copy must match the current design and say when something is planned rather than built.
- Public copy names no specific companies or products, including competitors.

## Interface design

- All Meerkat interfaces are dark only. Light mode is banned, so don't add or propose a light theme.

## Git workflow

- `main` always builds.
- Work happens on short-lived branches and merges through a pull request after CI passes, even when working alone.
- Create a `release/0.5` style branch only when a release needs a fix that `main` cannot take.
- Commits follow Conventional Commits, such as `feat(agent): add file watcher`. Commits made before this rule stay as they are. Scopes are listed in [naming.md](naming.md#commit-scopes).
- Pull request titles follow Conventional Commits too, because the squash merge uses the title as the commit on `main`. CI checks the title.
- `main` is protected by the `Protect main` ruleset: pull requests only, all CI jobs passing, linear history, every conversation resolved, and an automatic Copilot review. Nobody can bypass it.
- `v*` tags are protected by the `Protect release tags` ruleset: once pushed, a release tag can't be moved or deleted. A bad release gets a new version, not a retag. Nobody can bypass it.
- Copilot review follows `.github/copilot-instructions.md`. Update it when a rule in `CLAUDE.md` changes.

## Releases

- A pushed tag triggers CI to build binaries and container images, generate the SBOM, sign everything, and publish a GitHub release.
- Release automation uses GoReleaser, with signing through Sigstore Cosign. The configuration is in `.goreleaser.yaml` and `.github/workflows/release.yml`.
- Signing is keyless, tied to the release workflow's GitHub identity, so there is no signing key to store or rotate. [SECURITY.md](../SECURITY.md#verifying-a-release) shows how to verify a release.
- Images are published to `ghcr.io/meerkat-mft/<component>`. Release candidates don't move the `latest` tag.
- `CHANGELOG.md` follows the Keep a Changelog format. A pull request with a change users would notice adds a line under `[Unreleased]`. Releasing moves those lines under the new version.
- Security fixes get their own advisory.

## Support and deprecation

- During 0.x, the only promise is to fix security issues in the latest release.
- From 1.0, a removed feature gets at least one minor release of warning.
- From 1.0, each major version has a published support period.

## Toolchain and dependencies

- Use the current stable Go version, and keep it up to date.
- Pin dependencies, and update them through automated pull requests. GitHub Actions are pinned to full commit hashes.
- Scan with `govulncheck` in CI.
- Add dependencies sparingly, especially in the agent.
- Review any dependency that touches cryptography.
