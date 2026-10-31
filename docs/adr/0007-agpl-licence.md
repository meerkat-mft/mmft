# 0007. AGPL licence

Status: Accepted
Date: 2026-10-31

## Context

MFT's central problem is trust. The licence must allow inspection without letting others resell the work as a closed service.

## Decision

Meerkat is licensed under AGPL. The project keeps the right to relicense, for example through a contributor agreement, from the first outside contribution.

## Alternatives considered

- **Closed source:** simple and fully owned, but nobody can check security claims.
- **Source-available:** inspectable, but it is not open source and draws fewer contributors.
- **Permissive licence:** the most goodwill, but others could resell the work as a closed service.

## Consequences

Anyone can audit the code, and that builds trust only if audits, a security policy, and fast fixes follow. AGPL deters some companies from using or contributing.
