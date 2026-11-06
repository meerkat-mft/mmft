# Shared setup for the lab scripts, which source this file from lab/. It
# starts the lab, the orchestrator, and the admin machine, and enrolls agents.
# Fingerprints travel from the agents to the admin machine through the
# calling script, never through the orchestrator, as ADR 0011 requires.

# Lab placeholders, never real secrets. compose.yaml holds the token's hash.
admin_token="lab-only-admin-token-not-a-secret"
passphrase="lab-only-passphrase-not-a-secret"

admin=/var/lib/mmft/admin
relay=/var/lib/mmft/relay
outbox=/var/lib/mmft/outbox
inbox=/var/lib/mmft/inbox
# relay_cmd is what start_relay runs. deliver.sh uses the test relay instead.
relay_cmd=${relay_cmd:-mmft-relay serve}
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
# clear reason. Once start_relay has run, it also points the orchestrator at
# the relay.
start_orchestrator() {
  # shellcheck disable=SC2086 # the relay options are deliberately split
  docker compose exec -d -T "$@" ${relay_fp:+-e MMFT_RELAY_ADDRESS=relay:7445 -e MMFT_RELAY_CERTIFICATE_SHA256=$relay_fp} \
    orchestrator sh -c "exec mmft-orchestrator serve >>/var/log/mmft/orchestrator.log 2>&1"
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
# creates its identity, and starts it with $relay_cmd. It sets relay_fp, the
# relay certificate hash the orchestrator gives agents with each ticket.
start_relay() {
  in_lab orchestrator cat /var/lib/mmft/ca/ca.crt | put relay "$relay/connection-ca.crt"
  ticket_key=$(in_lab orchestrator mmft-orchestrator ca relay-settings | field relay_ticket_key)
  relay_fp=$(in_lab relay mmft-relay init | field relay_certificate_sha256)
  docker compose exec -d -T -e MMFT_RELAY_TICKET_KEY="$ticket_key" -e MMFT_RELAY_CAPTURE_DIR="$relay/capture" \
    relay sh -c "exec $relay_cmd >>$relay/relay.log 2>&1"
  echo "Waiting for the relay to listen on 7445..."
  for _ in $(seq 1 30); do
    if in_lab relay nc -z localhost 7445 2>/dev/null; then
      echo "The relay is ready."
      return 0
    fi
    sleep 1
  done
  echo "FAIL: the relay did not start listening within 30 seconds"
  exit 1
}

# setup_lab starts the lab, the relay, and the orchestrator, and sets up the
# admin machine with a trust root, an administrator key, and its certificate.
# It sets ca_fp, root_fp, and relay_fp. Arguments go to start_orchestrator.
setup_lab() {
  echo "Starting the lab..."
  docker compose up --build --detach --wait --wait-timeout 120
  in_lab orchestrator mmft-orchestrator migrate >/dev/null
  ca_fp=$(in_lab orchestrator mmft-orchestrator ca init | field ca_fingerprint)
  start_relay
  start_orchestrator "$@"

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

# enroll_both enrolls and approves agent-a and agent-b, collecting their
# fingerprints in the directory WORK.
enroll_both() {
  echo "Enrolling and approving both agents..."
  for host in agent-a agent-b; do
    token "$host" | field token | put "$host" "$spool/token"
    install "$host" "$host" "$state" >/dev/null
    in_lab "$host" mmft-agent fingerprint --dir "$state" --json >>"$1/fingerprints.json"
  done
  approve "$1/fingerprints.json" >/dev/null
}

# run_with_boxes runs both agents with an outbox, an inbox, and a spool for
# sealed files, logging to $spool/run.log.
run_with_boxes() {
  echo "Starting both agents with an outbox and inbox..."
  for host in agent-a agent-b; do
    in_lab "$host" mkdir -p "$spool/sealed"
    docker compose exec -d -T "$host" sh -c \
      "exec mmft-agent run --dir $state --outbox $outbox --inbox $inbox --spool $spool/sealed >>$spool/run.log 2>&1"
  done
}

# send_file NAME OUT sends NAME from agent-a to agent-b with `mmft delivery
# send --wait`, writing the run's JSON to OUT. It retries while the agents
# are still connecting, which the API refuses with 409, and returns the
# command's exit code.
send_file() {
  for _ in $(seq 1 30); do
    code=0
    in_lab admin mmft delivery send --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
      --workspace lab --from agent-a --to agent-b --file "$1" --wait --timeout 2m >"$2" 2>"$2.err" || code=$?
    grep -q 409 "$2.err" || return "$code"
    sleep 1
  done
  return "$code"
}

# finish reports the result and exits.
finish() {
  if [ "$fails" -ne 0 ]; then
    echo "$fails checks failed"
    exit 1
  fi
  echo "All checks passed"
}
