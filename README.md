<p align="center">
  <img src="assets/brand/meerkat-logo.svg" alt="Meerkat MFT logo" width="160">
</p>

# Meerkat MFT

Meerkat MFT is an open source managed file transfer orchestrator for moving files between systems. You bring the sources and destinations. Meerkat decides what moves and when, and it records what happened.

> **Status:** early development. There is no working software yet, and this project is not ready for any real use.

## Design goals

- **Nothing listens on the public internet.** Agents connect outbound, and customers keep their own endpoints.
- **The orchestrator cannot read file contents or credentials.** It sees everything else.
- **Every transfer leaves evidence.** Audit records are hash-chained and verifiable outside the database.
- **Everything is available through the API.** The console and CLI use the same public REST API.

## Documentation

- [Product requirements](docs/planning/prd.md)
- [Roadmap](docs/planning/roadmap.md)
- [Glossary](GLOSSARY.md)
- [Architecture decisions](docs/adr/)
- [Conventions](docs/conventions.md)

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Licence

Meerkat MFT is licensed under the [GNU Affero General Public License v3.0](LICENSE).
