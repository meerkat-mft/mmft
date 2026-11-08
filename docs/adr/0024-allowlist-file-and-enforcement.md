# 0024. Allowlist file format and enforcement

Status: Accepted
Date: 2026-11-08

Refines [ADR 0013](0013-agent-allowlists.md) and [ADR 0021](0021-manual-deliveries-in-m1.md).

## Context

ADR 0013 makes each agent's allowlist a local file that only root can change, and says what it lists. It leaves the file's exact format, how the agent proves the file is root's alone, and how a path is checked and then opened. ADR 0021 limited M1's manual deliveries to an outbox and inbox set by flags, and said a new ADR would record how they change when the allowlist arrives.

Deployment tools will write the file on many hosts, so its format is hard to change once it ships. A gap in how a path is checked against it, or how a file is opened afterwards, would let a compromised orchestrator or administrator key reach paths the host never allowed.

## Decision

**The file.** `mmft-agent run` reads `/etc/mmft/allowlist.yaml` once when it starts, or the file named by `--allowlist`. A change takes effect when the agent restarts. Version 1 is one YAML document:

```yaml
version: 1
read:
  - /srv/outbox
write:
  - /srv/inbox
send_to:
  - workspace: finance
  - agent: 0190f9c3-2b7d-7e01-8000-0000000000a1
receive_from:
  - workspace: finance
approvals: 2
```

- **Decoding is strict.** Unknown or repeated fields, nulls, anchors, aliases, tags, and a second document are refused, so the file means exactly what it says. The parser is `go.yaml.in/yaml/v3`, with these checks added.
- **A path entry is a directory, and allows everything under it.** It must be in the canonical absolute form that flow versions use ([ADR 0022](0022-flow-version-format.md)), and must exist when the agent starts. Its links are resolved then, and the agent holds the directory open from then on.
- **Peers are named by agent ID or by workspace,** never by agent name. ADR 0013 said "by name". Names can change, and an agent ID is bound to the agent's keys, for the reason ADR 0022 gives for cards. A peer is matched against the identity statement the agent verified to its own pinned root.
- **`approvals`** is how many administrators must sign a flow version. It must be at least 1 when the file lists anything.
- **No bytes, or a document with no fields, denies everything,** and so does a missing file. The agent still starts and connects, so it can be enrolled and approved before its allowlist is written.

**Only root can change it.** The agent opens the file without following a link, and reads and hashes the bytes of that one open file. It refuses to start unless the file is a regular file owned by root and writable by no group or other user, every directory above it up to `/` is the same, and the agent itself is not root. A writable directory would let the file be replaced, and an agent running as root could change the file itself.

**Checking and opening a path.** For each path, the agent:

1. requires its canonical absolute form, so `..` never reaches the file system;
2. resolves its links, and requires the result to be an entry or under one, comparing whole path segments, so `/srv/out` doesn't allow `/srv/outbox`;
3. opens the directory through the handle it holds for that entry, using Go's `os.Root`, which never follows a link out of it, and requires the directory opened to be the one it checked;
4. from then on opens, creates, and links files only through that directory handle. A file it reads must be a regular file that is not a link, and the file opened must be the one checked.

So a link swapped in anywhere along the path after the check can't lead outside the entry, and one that leads elsewhere inside it is refused because the opened directory or file isn't the one checked. This uses only the standard library.

**The hash.** The agent sends the SHA-256 of the file's bytes, or of no bytes when there is no file, in each `Hello`. The orchestrator requires 32 bytes and keeps the latest on the agent's presence row. The agent keeps the hash it last started with in its state directory and logs `allowlist changed` with both hashes when it differs. When agent audit events arrive, the agent records that change as one.

**Manual deliveries keep their flags, inside the allowlist.** `--outbox` and `--inbox` still name the directories manual deliveries use, and deliveries still name a bare file. The outbox must be readable and the inbox writable under the allowlist, and the spool must be outside every entry, or the agent refuses to start. Each delivery checks and opens its directory as above, and its peer must be in `send_to` or `receive_from`. A refusal is reported as `path_not_allowed` or `peer_not_allowed`, never with a path.

**Windows** denies everything until the Windows agent is defined, because the owner checks above are for Linux.

## Alternatives considered

- **JSON in `allowlist.yaml`:** no new dependency, since JSON is valid YAML. But a deployment tool and a person writing YAML would be surprised, and the name promises YAML.
- **Our own parser for a small YAML subset:** no dependency, but new parsing code in the file that guards everything else.
- **Peers by agent name, as ADR 0013 said:** easier to read, but a name can be reused by a new agent, which would silently change what the allowlist means.
- **Checking the path, then opening it by path:** simpler, but anything swapped in between is opened without a check.
- **Opening every path component with no links at all:** stricter, but it needs code for each platform, and the held entry handle already keeps every open inside the entry.
- **Replacing the outbox and inbox flags with paths in each manual run:** closer to flows, but it changes the manual-run API just as flow runs arrive to take its place.
- **Ignoring a missing entry:** a deployment tool could create directories later, but a typo would show up only as denied deliveries.
- **Reloading the file without a restart:** changes apply sooner, but a half-written file could be read, and a deployment tool restarts the service anyway.

## Consequences

- A compromised orchestrator or administrator key can reach only the directories and agents the host allowed, and only through links that stay inside an allowed directory.
- The agent must run under its own account, never root, and a host must create the allowlist's directories before the agent starts.
- An agent with no allowlist connects but does nothing, so enrollment doesn't wait on the allowlist.
- The flags for manual deliveries stay until manual runs are retired. Flow runs use the same checks.
- Error codes `path_not_allowed` and `peer_not_allowed` join the agent's published codes.
- Revisit this when Windows enforcement or remote endpoints arrive, which need entries the version 1 format can't express.
