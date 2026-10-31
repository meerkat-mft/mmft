# Naming conventions

Use **Meerkat MFT** in human-facing text and **`mmft`** in everything technical, followed by what the part does. Domain words come from [GLOSSARY.md](../GLOSSARY.md).

## Components

| Item | Name |
| --- | --- |
| CLI | `mmft` |
| Orchestrator binary and container | `mmft-orchestrator` |
| Relay binary and container | `mmft-relay` |
| Agent binary and container | `mmft-agent` |
| Console container | `mmft-console` |

Each service is its own binary, so orchestrator code never ships on systems that run only an agent.

## Installed names

| Item | Name |
| --- | --- |
| Linux services | `mmft-orchestrator.service`, `mmft-relay.service`, `mmft-agent.service` |
| Windows service | Name `mmft-agent`, display name "Meerkat MFT Agent" |
| OS user and group | `mmft` |
| Linux config | `/etc/mmft/<service>.yaml`, such as `/etc/mmft/agent.yaml` |
| Linux data | `/var/lib/mmft/` |
| Linux logs | `/var/log/mmft/` |
| Windows config and data | `C:\ProgramData\Meerkat MFT\` |
| Compose project | `mmft` |
| Postgres database | `mmft` |

## Code and interfaces

| Item | Convention | Example |
| --- | --- | --- |
| Go module | `mmft.dev/mmft` | |
| Environment variables | `MMFT_` prefix | `MMFT_ORCHESTRATOR_URL` |
| Metrics | `mmft_` prefix | `mmft_deliveries_total` |
| REST API | `/api/v1/` with plural glossary nouns | `/api/v1/flows`, `/api/v1/runs` |
| Audit event types | `noun.past_tense_verb` | `flow.version_created`, `delivery.failed` |

## CLI commands

Commands follow `mmft <noun> <verb>`, using glossary nouns.

```text
mmft flow list
mmft flow validate invoices.json
mmft run start invoices-nl
mmft agent enroll
mmft audit verify
```
