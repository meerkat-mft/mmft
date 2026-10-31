# 0005. Go and TypeScript, deployed with Compose only

Status: Accepted
Date: 2026-10-31

## Context

The agent must be a small single binary for Linux and Windows, the services are network-heavy, and one person builds this in spare time. Customers run Meerkat themselves on any public or private cloud.

## Decision

The orchestrator, relay, agent, and CLI are written in Go, unless there is a good reason to use something else. The console is TypeScript and React and uses only the public API. Everything lives in one monorepo. Version 1 ships for Docker Compose only, with services kept stateless so that Kubernetes and high availability can follow.

## Alternatives considered

- **Rust:** stronger memory-safety guarantees, but slower to build with in limited time.
- **Kubernetes from the start:** the expected route to high availability, but it adds packaging and test work, and some mid-sized firms do not run it.
- **VM images and installers:** broad reach, but too much packaging for one person.

## Consequences

One toolchain and one repo stay consistent. There is no automatic failover in version 1, so backup and restore must be tested and recovery targets published. Some buyers will rule Meerkat out until high availability ships. FIPS 140-3 validation is not a requirement, but custom cryptography is avoided so it stays possible.
