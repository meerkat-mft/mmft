# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The orchestrator issues one-use enrollment tokens and enrolls agents that prove they hold their keys.
- Signed releases: each tag publishes binaries, container images, and SBOMs, signed with Sigstore Cosign. See SECURITY.md for how to verify them.
