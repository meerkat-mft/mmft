# Roadmap

Milestones M0 to M4 build the MVP, and their scope and exit tests are in the [PRD](prd.md#milestones). Releases after the MVP are ordered, not dated. Real demand from a design partner can reorder them.

All 0.x releases are beta, including the MVP. Breaking changes are allowed in 0.x, and they are documented in release notes. ADRs that say "version 1" mean the MVP.

## Stages

| Stage | Reached at | What it proves |
| --- | --- | --- |
| **Proof of concept** | 0.1 (M1) | A file moves between two agents, and the orchestrator cannot read it |
| **MVP** | 0.4 (M4) | Scheduled flows between agents run unattended and leave verifiable evidence |
| **First partner-ready release** | 0.5 | Files can be exchanged with an external SFTP server |
| **Stable release** | 1.0 | Meerkat makes the stability promises below |

## Releases

### 0.1 to 0.3: Early builds

- **0.1 (M1):** the skeleton
- **0.2 (M2):** reliable runs
- **0.3 (M3):** operable through the console

### 0.4: MVP

Everything in the [PRD's MVP scope](prd.md#mvp-scope). Files move only between systems running an agent.

### 0.5: Partner exchange

- SFTP connector
- Bundled agent
- Sealed credentials
- PGP encryption and decryption

This is the first release to show a design partner.

### 0.6: Cloud storage

- S3 connector
- Azure Blob connector, including the Azure Blob SFTP pattern
- Staging storage as a route between agents
- Event-based triggers

### 0.7: Enterprise access

- OIDC sign-in
- SCIM provisioning
- Custom roles
- Four-eyes approval for flow changes

### 0.8: Windows estates

- SMB connector
- File name masking

### 0.9: Resilience

- High availability
- Kubernetes support with Helm
- External pen test and security audit, published

### 1.0: Stable

The maintainer promotes a release to 1.0 by decision, not by feature count. More 0.x releases can come first, such as 0.10.

The release must be able to keep these promises:

- The REST API and flow format stay compatible within a major version.
- Upgrades work from the previous release, with no data loss and with tested migration steps.
- Agents from the previous release keep working during an upgrade.
- Security fixes have a published support period.
- Real users have run it in production without data loss.
- An external audit has been completed and its findings addressed.

### Later, if demand appears

- Malware scanning, DLP, compression, and format translation
- A hub route for central inspection
- Content-based rules
- An encrypted spool on the relay
- Vault and HSM integration
- A Terraform provider
- A partner web portal and ad hoc sharing
- AS2, OFTP2, and EBICS connectors

## Never

- Loops, waiting joins, or custom scripts in flows
- Meerkat listening on the public internet
- An orchestrator that can read file contents or credentials
