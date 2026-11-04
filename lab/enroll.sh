#!/bin/sh
# Enrolls both lab agents unattended, as a deployment tool would, and checks
# that a used token, an expired token, and a changed fingerprint are refused.
# Fingerprints travel from the agents to the admin machine through this script,
# never through the orchestrator, as ADR 0011 requires.
set -eu
cd "$(dirname "$0")"

# Lab placeholders, never real secrets. compose.yaml holds the token's hash.
admin_token="lab-only-admin-token-not-a-secret"
passphrase="lab-only-passphrase-not-a-secret"

admin=/var/lib/mmft/admin
state=/var/lib/mmft/agent
spool=/var/lib/mmft/spool

fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
in_lab() { docker compose exec -T "$@"; }
# field reads one string field from the JSON on stdin.
field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p"; }
# put writes stdin to a file only its owner can read, inside a container.
put() { docker compose exec -T "$1" sh -c 'umask 077; cat > "$1"' sh "$2"; }
expect_code() {
  want=$1
  shift
  if "$@" >/dev/null 2>&1; then got=0; else got=$?; fi
  if [ "$got" = "$want" ]; then pass "$label"; else fail "$label (exit $got, want $want)"; fi
}

cleanup() { docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose up --build --detach --wait --wait-timeout 120

# The orchestrator: schema, connection CA, and service.
in_lab orchestrator mmft-orchestrator migrate >/dev/null
ca_fp=$(in_lab orchestrator mmft-orchestrator ca init | field ca_fingerprint)
docker compose exec -d -T orchestrator mmft-orchestrator serve
for _ in $(seq 1 30); do
  in_lab orchestrator nc -z localhost 7444 2>/dev/null && break
  sleep 1
done

# The admin machine: trust root, administrator key, and its certificate.
printf '%s' "$passphrase" | put admin "$admin/passphrase"
printf '%s' "$admin_token" | put admin "$admin/api-token"
root_fp=$(in_lab admin mmft trust init --dir "$admin/root" --passphrase-file "$admin/passphrase" | field fingerprint)
admin_fp=$(in_lab admin mmft admin init --dir "$admin/key" --owner lab.admin --passphrase-file "$admin/passphrase" | field fingerprint)
in_lab admin mmft trust certify-admin --root-dir "$admin/root" --root-fingerprint "$root_fp" \
  --passphrase-file "$admin/passphrase" --request "$admin/key/administrator.pub.json" \
  --admin-fingerprint "$admin_fp" --out "$admin/admin.cert.json" >/dev/null

# token NAME prints the JSON from `mmft agent token`.
token() {
  in_lab admin mmft agent token --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
    --workspace lab --name "$1" --orchestrator orchestrator:7443 --root-fingerprint "$root_fp"
}
# install HOST NAME DIR runs `mmft-agent install` with a token already on HOST.
install() {
  in_lab "$1" mmft-agent install --dir "$3" --orchestrator orchestrator:7443 --name "$2" \
    --token-file "$spool/token" --ca-fingerprint "$ca_fp" --root-fingerprint "$root_fp"
}
# approve FILE runs `mmft agent approve` with fingerprints from FILE on this machine.
approve() {
  put admin "$admin/fingerprints.json" <"$1"
  in_lab admin mmft agent approve --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
    --admin-dir "$admin/key" --passphrase-file "$admin/passphrase" --certificate "$admin/admin.cert.json" \
    --root-public "$admin/root/root.pub.json" --root-fingerprint "$root_fp" --fingerprints "$admin/fingerprints.json"
}

work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT

# Unattended enrollment of both agents.
for host in agent-a agent-b; do
  token "$host" | field token | put "$host" "$spool/token"
  label="$host installs with its token"
  expect_code 0 install "$host" "$host" "$state"
  in_lab "$host" mmft-agent fingerprint --dir "$state" --json >>"$work/fingerprints.json"
done
label="agents wait for approval"
expect_code 5 in_lab agent-a mmft-agent identity --dir "$state"
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
printf '{"agent_id":"%s","agent_name":"agent-c","fingerprint":"%s"}\n' "$c_id" "$a_fp" >"$work/changed.json"
label="a changed fingerprint is refused"
expect_code 4 approve "$work/changed.json"
label="the refused agent stays unapproved"
expect_code 5 in_lab agent-a mmft-agent identity --dir "$spool/c"

if [ "$fails" -ne 0 ]; then
  echo "$fails checks failed"
  exit 1
fi
echo "All checks passed"
