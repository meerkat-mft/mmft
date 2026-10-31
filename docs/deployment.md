# Deployment

Draft for the MVP. It describes where Meerkat's parts run and what must never be reachable from the internet.

## Network rules

- The orchestrator, relay, console, and Postgres belong on a private network.
- Agents connect outbound to the orchestrator and relay. Agents accept no connections.
- The console and API are for administrators on the private network.
- Postgres is reachable only from the orchestrator.

## Supported topologies

| Topology | How agents connect | Status |
| --- | --- | --- |
| **Single network** | Agents reach the orchestrator and relay directly | Supported |
| **Several sites or clouds** | Agents connect over a site-to-site VPN or private link that the customer runs | Supported |
| **Evaluation on one host** | Everything runs in Docker Compose on one host | Supported, not for production |
| **Agents on a network you don't control** | No private path exists | Not supported in the MVP |
| **Orchestrator or relay exposed to the internet** | Agents connect over the public internet | Not supported |

The claim that nothing needs to face the internet depends on these topologies. Exposing the orchestrator or relay publicly removes that protection, even with mTLS.

Partners don't run in any of these topologies. They use an endpoint the customer owns, through a connector on the roadmap.

## Handling untrusted metadata

Everything an agent reports, including file names and error codes, is untrusted input.

- The API validates length and format, and rejects values that fail.
- Agents report stable error codes, not raw error output.
- The console displays this data as text and never as markup.
- The console is served with a strict content security policy: same-origin scripts, styles, and API connections only, with framing denied.
- Logs escape control characters.
