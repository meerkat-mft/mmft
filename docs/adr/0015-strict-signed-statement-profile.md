# 0015. Strict profile for signed statements

Status: Accepted
Date: 2026-11-01

Refines [ADR 0012](0012-signed-statements-and-flow-approval.md).

## Context

A review of the signed statement library found no way to forge a statement, but found that general JSON and base64 parsing accepts several forms of one envelope, and that a threshold based on distinct keys can be met by one person holding two keys. DSSE leaves some of these choices open, and requires verifiers to accept URL-safe base64.

## Decision

Meerkat uses a stricter profile of DSSE:

- Only standard padded base64 is accepted, with no line breaks. Meerkat deliberately departs from DSSE's requirement to accept URL-safe base64, so that each value has one form.
- Envelopes reject duplicate and differently cased known fields, missing required fields, and trailing data. Unknown fields are ignored.
- A statement's identity is a hash of its payload type and payload. Replay and audit logic use this, never a hash of the envelope, because signatures can be reordered or added.
- Each trusted key has an owner, and thresholds count distinct owners. A trusted set can't contain keys that share an Ed25519 or ML-DSA half, or one key under two owners.
- Verification returns which keys signed, and callers must check scope against them, such as an automation key's workspace.
- Small-order Ed25519 public keys are rejected, because they would silently remove the hybrid property.

## Alternatives considered

- **Accept URL-safe base64 as DSSE requires:** better compatibility, but no one else needs to read these statements, and two forms add risk.
- **Count distinct keys:** simpler, but one administrator's old and new keys could meet a four-eyes threshold during renewal.
- **`encoding/json/v2`:** stricter by default, but it needs an experiment flag in Go 1.27.

## Consequences

Standard DSSE tools can read Meerkat's statements, but envelopes that use URL-safe base64 are refused. Enrollment must also prove that an agent holds its private keys, which [#5](https://github.com/meerkat-mft/mmft/issues/5) covers. Verification cost grows with the trusted set, so callers pass only the keys that could have signed, not a whole fleet.
