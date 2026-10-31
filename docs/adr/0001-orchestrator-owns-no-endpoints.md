# 0001. The orchestrator owns no endpoints and agents connect outbound only

Status: Accepted
Date: 2026-10-31

## Context

Internet-facing MFT servers have been mass-exploited. Traditional products host the listener that partners connect to, so they carry that attack surface themselves.

## Decision

Meerkat hosts no partner-facing endpoints. Customers bring every source and destination, including any managed SFTP service a partner connects to. Nothing Meerkat runs listens on the public internet. Agents accept no inbound connections and dial out to the orchestrator and relay over mTLS. The orchestrator and relay listen only on an internal network or private link.

## Alternatives considered

- **Hosted SFTP and HTTPS servers:** the market norm, but they recreate the attack surface this project exists to avoid.
- **An edge gateway in a DMZ:** smaller exposure, but it still listens on the internet and adds a component to harden.
- **Agents that accept internal connections:** simpler for agent-to-agent transfers, but gives up outbound-only agents.

## Consequences

The internet-facing attack surface is removed. Partners who expect the customer to host an endpoint need a customer-provided service such as Azure Blob SFTP or AWS Transfer Family. Partner logins are then recorded outside Meerkat, and customers with no such service must run their own. Revisit if real customers cannot adopt Meerkat without a hosted endpoint.
