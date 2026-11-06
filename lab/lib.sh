# Shared setup for the lab scripts, which source this file from lab/. It
# starts the lab, the orchestrator, and the admin machine, and enrolls agents.
# Fingerprints travel from the agents to the admin machine through the
# calling script, never through the orchestrator, as ADR 0011 requires.

# Lab placeholders, never real secrets. compose.yaml holds the token's hash.
admin_token="lab-only-admin-token-not-a-secret"
passphrase="lab-only-passphrase-not-a-secret"

admin=/var/lib/mmft/admin
relay=/var/lib/mmft/relay
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

# start_orchestrator runs the orchestrator service, with any extra `docker
# compose exec` options such as -e NAME=VALUE, and waits until both the agent
# service (7443) and the API (7444) answer, so a slow start fails here with a
# clear reason.
start_orchestrator() {
  docker compose exec -d -T "$@" orchestrator mmft-orchestrator serve
  echo "Waiting for the orchestrator to listen on 7443 and 7444..."
  for _ in $(seq 1 30); do
    if in_lab orchestrator nc -z localhost 7443 2>/dev/null && in_lab orchestrator nc -z localhost 7444 2>/dev/null; then
      echo "The orchestrator is ready."
      return 0
    fi
    sleep 1
  done
  echo "FAIL: the orchestrator did not start listening within 30 seconds"
  exit 1
}

# start_relay gives the relay the orchestrator's connection CA and ticket key,
# creates its identity on first use, and starts it. It sets relay_fp, the
# relay certificate hash the orchestrator will give agents with each ticket.
start_relay() {
  in_lab orchestrator cat /var/lib/mmft/ca/ca.crt | put relay "$relay/connection-ca.crt"
  ticket_key=$(in_lab orchestrator mmft-orchestrator ca relay-settings | field relay_ticket_key)
  if ! in_lab relay test -f "$relay/relay.crt"; then
    in_lab relay mmft-relay init >/dev/null
  fi
  docker compose exec -d -T -e MMFT_RELAY_TICKET_KEY="$ticket_key" relay sh -c "exec mmft-relay serve >>$relay/relay.log 2>&1"
  echo "Waiting for the relay to listen on 7445..."
  for _ in $(seq 1 30); do
    if in_lab relay nc -z localhost 7445 2>/dev/null; then
      relay_fp=$(in_lab relay grep -m1 '"event":"started"' "$relay/relay.log" | field relay_certificate_sha256)
      echo "The relay is ready."
      return 0
    fi
    sleep 1
  done
  echo "FAIL: the relay did not start listening within 30 seconds"
  exit 1
}

# setup_lab starts the lab, the orchestrator, and the relay, and sets up the
# admin machine with a trust root, an administrator key, and its certificate.
# It sets ca_fp, root_fp, and relay_fp. Arguments go to start_orchestrator.
setup_lab() {
  echo "Starting the lab..."
  docker compose up --build --detach --wait --wait-timeout 120
  in_lab orchestrator mmft-orchestrator migrate >/dev/null
  ca_fp=$(in_lab orchestrator mmft-orchestrator ca init | field ca_fingerprint)
  start_orchestrator "$@"
  start_relay

  echo "Setting up the admin machine..."
  printf '%s' "$passphrase" | put admin "$admin/passphrase"
  printf '%s' "$admin_token" | put admin "$admin/api-token"
  root_fp=$(in_lab admin mmft trust init --dir "$admin/root" --passphrase-file "$admin/passphrase" | field fingerprint)
  admin_fp=$(in_lab admin mmft admin init --dir "$admin/key" --owner lab.admin --passphrase-file "$admin/passphrase" | field fingerprint)
  in_lab admin mmft trust certify-admin --root-dir "$admin/root" --root-fingerprint "$root_fp" \
    --passphrase-file "$admin/passphrase" --request "$admin/key/administrator.pub.json" \
    --admin-fingerprint "$admin_fp" --out "$admin/admin.cert.json" >/dev/null
}

# token NAME prints the JSON from `mmft agent token`.
token() {
  in_lab admin mmft agent token --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
    --workspace lab --name "$1" --orchestrator orchestrator:7443 --root-fingerprint "$root_fp"
}
# install HOST NAME DIR runs `mmft-agent install` with a token already on HOST.
install() {
  in_lab "$1" mmft-agent install --dir "$3" --orchestrator orchestrator:7443 --workspace lab --name "$2" \
    --token-file "$spool/token" --ca-fingerprint "$ca_fp" --root-fingerprint "$root_fp"
}
# approve FILE runs `mmft agent approve` with fingerprints from FILE on this machine.
approve() {
  put admin "$admin/fingerprints.json" <"$1"
  in_lab admin mmft agent approve --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
    --admin-dir "$admin/key" --passphrase-file "$admin/passphrase" --certificate "$admin/admin.cert.json" \
    --root-public "$admin/root/root.pub.json" --root-fingerprint "$root_fp" --fingerprints "$admin/fingerprints.json"
}

# finish reports the result and exits.
finish() {
  if [ "$fails" -ne 0 ]; then
    echo "$fails checks failed"
    exit 1
  fi
  echo "All checks passed"
}
