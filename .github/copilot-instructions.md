# Review instructions for Meerkat MFT

Meerkat MFT is a managed file transfer platform written in Go, with a TypeScript console. Review pull requests against the rules below first. Generic style comments matter less than these.

## Hard rules

Flag any change that breaks one of these as a blocking issue.

- The orchestrator never reads file contents or credentials. Watch for orchestrator code that receives, stores, logs, or decrypts payload bytes, keys, or secrets.
- Flow approval and credential entry happen only in the signed CLI, never in the console or the API that the console uses.
- No custom cryptography. Cryptography must come from reviewed libraries, such as the Go standard library or `filippo.io/age`. Flag hand-rolled ciphers, MACs, key derivation, or signature schemes.
- File names never go in audit events, delivery manifests, or receipts. They belong only in `delivery_files`.
- Every console feature uses the public API. The console has no private endpoints.
- All interfaces are dark only. Flag any light theme or theme switch.
- No real credentials, private keys, or customer files, including in test fixtures.
- Public copy names no specific companies or products.

## Project rules

- A schema change also updates `docs/data-model.md`.
- A change under `api/` also regenerates `gen/` with `scripts/check-api.sh --write`. Nothing in `gen/` is edited by hand.
- A change that is expensive to reverse needs an ADR in `docs/adr/`. An accepted ADR is never edited; a new ADR supersedes it. The one allowed edit is setting the old ADR's status to `Superseded by NNNN`, in the same pull request as the new ADR.
- Terms follow `GLOSSARY.md` exactly, in code, comments, and docs.
- GitHub Actions are pinned to full commit hashes.
- New dependencies are added sparingly, especially in the agent. Any dependency that touches cryptography needs a close look.
- Database migrations run forward only.

## What helps most

- Security problems: missing authorization checks, untrusted metadata used without validation, secrets in logs, injection, and path traversal at delivery destinations.
- Correctness problems: unhandled errors, races, resource leaks, and missing tests for new behaviour.
- Keep comments short, and say what breaks and how. Skip praise and summaries of what the diff already shows.
