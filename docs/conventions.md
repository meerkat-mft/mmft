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

## Git workflow

- `main` always builds.
- Work happens on short-lived branches and merges through a pull request after CI passes, even when working alone.
- Create a `release/0.5` style branch only when a release needs a fix that `main` cannot take.
- Commits follow Conventional Commits, such as `feat(agent): add file watcher`. Commits made before this rule stay as they are.

## Releases

- A pushed tag triggers CI to build binaries and container images, generate the SBOM, sign everything, and publish a GitHub release.
- Release automation uses GoReleaser, with signing through Sigstore Cosign.
- `CHANGELOG.md` follows the Keep a Changelog format.
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
