# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The orchestrator issues one-use enrollment tokens and enrolls agents that prove they hold their keys.
- `mmft-agent install` enrolls an agent unattended, trusting the orchestrator only through the CA fingerprint in the install command, and `mmft-agent fingerprint` prints the value to compare before approval.
- `mmft agent approve --fingerprints` signs the identity of each pending agent whose fingerprint, ID, and name match the values collected from its host, refuses any other with exit code 4, and skips agents already approved. It never prompts.
- `mmft-agent identity` fetches the agent's signed identity and verifies it back to the pinned trust root. It exits with code 5 until the agent is approved.
- Signed releases: each tag publishes binaries, container images, and SBOMs, signed with Sigstore Cosign. See SECURITY.md for how to verify them.

### Security

- On Windows, `mmft` now refuses to create or read private key and passphrase files, because it can't yet check that they are private there. Use Linux, macOS, or WSL for `trust init`, `admin init`, `trust certify-admin`, and other commands that use them.
