# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The orchestrator issues one-use enrollment tokens and enrolls agents that prove they hold their keys.
- An agent's ID is derived from its keys, and its workspace comes from `mmft-agent install --workspace`, so the orchestrator can't choose either. See ADR 0019.
- A new token for an existing agent re-enrolls it with its own keys, so a lost token or a connection certificate that expired before approval can be recovered. A used token can be retried only while it is valid.
- `mmft-agent install` exits 3 for a safe repeat only when its settings match and its keys and a current certificate are in place. Other settings or damaged files exit 1, and an expired certificate re-enrolls with the new token.
- `mmft-agent install` enrolls an agent unattended, trusting the orchestrator only through the CA fingerprint in the install command, and `mmft-agent fingerprint` prints the value to compare before approval.
- `mmft agent token` creates a one-use enrollment token and prints every value `mmft-agent install` needs, as JSON.
- `mmft agent approve --fingerprints` signs the identity of each pending agent whose fingerprint, ID, workspace, and name match the values collected from its host, and refuses any other with exit code 4. It skips agents already approved only when they match too. It never prompts.
- `mmft agent approve` carries on past an API error for one agent, reports it under `failed`, and exits 1, so the report always says what changed.
- `GET /api/v1/agents/{agent_id}` returns one agent, and unknown API paths answer with a problem document.
- Exit codes are the same for `mmft` and `mmft-agent`, and are listed in the usage text and `docs/naming.md`.
- `mmft-agent identity` fetches the agent's signed identity and verifies it back to the pinned trust root. It exits with code 5 until the agent is approved.
- `mmft-agent run` keeps the agent connected to the orchestrator over one outbound stream, with a heartbeat every 30 seconds. It reconnects with backoff after a dropped connection or a restart, and renews its connection certificate once it is past half its lifetime, keeping the same key. An expired certificate stops it with exit 1 and says to install again with a new token.
- The agent listing and `GET /api/v1/agents/{agent_id}` return `agent_version` and `last_seen_at` once an agent has connected.
- `MMFT_CONNECTION_LIFETIME` sets how long the orchestrator's connection certificates last, from 2 minutes to the default 24 hours. Only the lab sets it short.
- `mmft-relay` forwards sealed files between agents with no direct path. Each side presents a relay ticket from the orchestrator, and an interrupted delivery resumes from the bytes the receiver already holds. The relay stores nothing. `mmft-relay init` creates its key and prints the certificate hash agents pin, and `mmft-relay serve` runs it. See ADR 0020.
- `mmft-orchestrator ca init` also creates the relay ticket key, and `mmft-orchestrator ca relay-settings` prints the connection CA certificate and ticket key that the relay needs, creating the key for a CA that predates it.
- Signed releases: each tag publishes binaries, container images, and SBOMs, signed with Sigstore Cosign. See SECURITY.md for how to verify them.

### Security

- The relay accepts an agent only with a connection certificate from the orchestrator's CA and a current relay ticket for that agent, side, and delivery, and agents accept only the relay whose certificate hash came with the ticket and take no more bytes than the sealed file holds. It bounds pairs, waiting sides, and streams per agent, and closes streams that stall. See ADR 0020 for the limits.
- An agent's open stream is checked again at every heartbeat, so revoking an agent ends its stream within 30 seconds instead of at its next reconnect. A stream that sends nothing for 90 seconds is closed.
- The orchestrator bounds what one network peer can hold open: 1024 connections per listener, 32 gRPC streams per connection, idle gRPC connections closed after 5 minutes, and read, write, and idle timeouts on the REST API. Before, a peer needing no credential could hold goroutines and descriptors open indefinitely.
- On Windows, `mmft` now refuses to create or read private key and passphrase files, because it can't yet check that they are private there. Use Linux, macOS, or WSL for `trust init`, `admin init`, `trust certify-admin`, and other commands that use them.
