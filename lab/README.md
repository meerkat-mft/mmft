# Lab

A local test lab in Docker containers, which runs on one laptop. Each script starts the lab, checks it, and removes it.

- `lab/smoke.sh` checks the networks, filesystems, and restarts that later failure tests rely on.
- `lab/enroll.sh` enrolls both agents unattended, as a deployment tool would: `mmft agent token`, `mmft-agent install`, `mmft-agent fingerprint --json`, `mmft agent approve --fingerprints`, and `mmft-agent identity`. It then checks that a used token, an expired token, and a changed fingerprint are refused. The fingerprints pass from the agents to the admin machine through the script, never through the orchestrator.

| Service | Networks | Purpose |
| --- | --- | --- |
| `orchestrator` | `core`, `site-a`, `site-b` | The orchestrator, which `enroll.sh` starts |
| `relay` | `core`, `site-a`, `site-b` | Placeholder for the relay |
| `postgres` | `core` | Database |
| `admin` | `core` | An administrator's machine, with the trust root and administrator key |
| `agent-a` | `site-a` | Source agent |
| `agent-b` | `site-b` | Destination agent |

All networks are internal. Agents can reach the orchestrator and relay, but not each other, Postgres, or the internet. Services run as an unprivileged user with a read-only filesystem. Each agent's spool is limited to 16 MB, so that full-disk tests are quick.

The Postgres password, the admin API token, and the passphrase in `compose.yaml` and `enroll.sh` are lab placeholders. Agent keys and the connection CA live on volumes, so they survive a container restart. The admin machine keeps its keys in memory only.

## Limits

- Linux containers only. The Windows agent needs a real Windows host, tracked separately.
- Containers share one kernel, so host-level attacks and service-account rules aren't fully tested.
- Docker's network behaviour differs from real networks and VPNs.

## Failure tests

Every milestone must pass the tests that apply to what it builds. Each test starts during an active delivery, unless it says otherwise.

| ID | Failure | How to cause it | Expected result | From |
| --- | --- | --- | --- | --- |
| K1 | Source agent killed | `docker compose kill agent-a` | Delivery resumes after restart, with no duplicate file | M2 |
| K2 | Destination agent killed | `docker compose kill agent-b` | No partial file at the destination, and delivery resumes | M2 |
| K3 | Relay killed | `docker compose kill relay` | Delivery resumes from its byte offset | M2 |
| K4 | Orchestrator killed | `docker compose kill orchestrator` | No evidence is lost, and agents buffer audit events | M2 |
| K5 | Postgres killed | `docker compose kill postgres` | Committed state survives, and work continues after restart | M2 |
| N1 | Agent loses the relay | `docker network disconnect` | Lease expires or delivery resumes, and no file is lost | M2 |
| N2 | Agent loses the orchestrator for longer than a lease | `docker network disconnect` | No delivery runs twice with a different result | M2 |
| N3 | Audit buffer fills while offline | Disconnect during a long run | The agent stops new work rather than losing evidence | M2 |
| D1 | Source spool full | File larger than 16 MB | Delivery fails with a clear reason and a notification | M2 |
| D2 | Destination spool full | Fill the spool during transfer | Delivery fails with a clear reason, and no partial file remains | M2 |
| C1 | Connection certificate expired | Short lifetime in the lab | The agent renews, or reports the failure clearly | M1 |
| C2 | Agent identity expired | Short lifetime in the lab | The agent refuses work and raises an alert | M2 |
| T1 | Sealed file altered at the relay | Test relay that flips a byte | The hash check fails, and nothing is decrypted | M1 |
| T2 | Sealed file truncated | Test relay that drops the end | The hash check fails, and nothing is decrypted | M1 |
| T3 | Sealed file swapped from another delivery | Test relay that replays a file | The signed manifest check fails | M1 |
| A1 | Flow outside the allowlist | Approve a flow with a blocked path | The flow fails with a clear reason, and doesn't partly run | M2 |
| A2 | Older flow version replayed | Offer a lower approved version | The agent refuses it | M2 |
| A3 | Hostile file name | Path traversal and control characters | The name is rejected or safely handled | M2 |
