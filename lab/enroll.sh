#!/bin/sh
# Enrolls both lab agents unattended, as a deployment tool would, and checks
# that a used token, an expired token, and a changed fingerprint are refused.
# Fingerprints travel from the agents to the admin machine through this script,
# never through the orchestrator, as ADR 0011 requires.
set -eu
cd "$(dirname "$0")"

. ./lib.sh
trap cleanup EXIT

setup_lab

work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT

# Unattended enrollment of both agents.
for host in agent-a agent-b; do
  token "$host" | field token | put "$host" "$spool/token"
  label="$host installs with its token"
  expect_code 0 install "$host" "$host" "$state"
  in_lab "$host" mmft-agent fingerprint --dir "$state" --json >>"$work/fingerprints.json"
done
for host in agent-a agent-b; do
  label="$host waits for approval"
  expect_code 5 in_lab "$host" mmft-agent identity --dir "$state"
done
label="both agents are approved with the collected fingerprints"
expect_code 0 approve "$work/fingerprints.json"
for host in agent-a agent-b; do
  label="$host verifies its identity to the pinned root"
  expect_code 0 in_lab "$host" mmft-agent identity --dir "$state"
done

# Repeat runs change nothing.
label="a repeat install is a safe repeat"
expect_code 3 install agent-a agent-a "$state"
label="a repeat approval skips approved agents"
expect_code 0 approve "$work/fingerprints.json"

# agent-b's used token, tried again from a fresh directory.
label="a used token is refused"
expect_code 4 install agent-b agent-b "$spool/again"

# A token past its expiry. Waiting an hour is too slow, so the lab moves its expiry.
token agent-late | field token | put agent-b "$spool/token"
in_lab postgres psql -q -U mmft -d mmft \
  -c "UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE agent_name = 'agent-late'"
label="an expired token is refused"
expect_code 4 install agent-b agent-late "$spool/late"

# An agent whose collected fingerprint differs from the keys the orchestrator holds.
token agent-c | field token | put agent-a "$spool/token"
install agent-a agent-c "$spool/c" >/dev/null
c_id=$(in_lab agent-a mmft-agent fingerprint --dir "$spool/c" --json | field agent_id)
a_fp=$(in_lab agent-a mmft-agent fingerprint --dir "$state" --json | field fingerprint)
printf '{"agent_id":"%s","workspace":"lab","agent_name":"agent-c","fingerprint":"%s"}\n' "$c_id" "$a_fp" >"$work/changed.json"
label="a changed fingerprint is refused"
expect_code 4 approve "$work/changed.json"
label="the refused agent stays unapproved"
expect_code 5 in_lab agent-a mmft-agent identity --dir "$spool/c"

finish
