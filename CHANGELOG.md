# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The orchestrator issues one-use enrollment tokens and enrolls agents that prove they hold their keys.
- An agent's ID is derived from its keys, and its workspace comes from `mmft-agent install --workspace`, so the orchestrator can't choose either. See ADR 0019.
- `mmft-agent install` enrolls an agent unattended, trusting the orchestrator only through the CA fingerprint in the install command, and `mmft-agent fingerprint` prints the value to compare before approval.
- `mmft agent token` creates a one-use enrollment token and prints every value `mmft-agent install` needs, as JSON.
- `mmft agent approve --fingerprints` signs the identity of each pending agent whose fingerprint, ID, workspace, and name match the values collected from its host, and refuses any other with exit code 4. It skips agents already approved only when they match too. It never prompts.
- `mmft agent approve` carries on past an API error for one agent, reports it under `failed`, and exits 1, so the report always says what changed.
- `GET /api/v1/agents/{agent_id}` returns one agent, and unknown API paths answer with a problem document.
- Exit codes are the same for `mmft` and `mmft-agent`, and are listed in the usage text and `docs/naming.md`.
- `mmft-agent identity` fetches the agent's signed identity and verifies it back to the pinned trust root. It exits with code 5 until the agent is approved.
- Signed releases: each tag publishes binaries, container images, and SBOMs, signed with Sigstore Cosign. See SECURITY.md for how to verify them.

### Security

- On Windows, `mmft` now refuses to create or read private key and passphrase files, because it can't yet check that they are private there. Use Linux, macOS, or WSL for `trust init`, `admin init`, `trust certify-admin`, and other commands that use them.
