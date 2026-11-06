#!/bin/sh
# Enrolls both lab agents, checks that both reach the relay, runs them, and
# checks that they stay connected, reconnect after an agent or orchestrator
# restart, and renew their connection certificates before they expire (failure
# test C1). The orchestrator issues 2-minute certificates here, so the whole
# run takes about four minutes.
set -eu
cd "$(dirname "$0")"

. ./lib.sh
trap cleanup EXIT

lifetime=--env=MMFT_CONNECTION_LIFETIME=2m
setup_lab "$lifetime"

work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT

echo "Enrolling and approving both agents..."
for host in agent-a agent-b; do
  token "$host" | field token | put "$host" "$spool/token"
  install "$host" "$host" "$state" >/dev/null
  in_lab "$host" mmft-agent fingerprint --dir "$state" --json >>"$work/fingerprints.json"
done
approve "$work/fingerprints.json" >/dev/null
enrolled_at=$(date +%s)
for host in agent-a agent-b; do
  label="$host verifies its identity"
  expect_code 0 in_lab "$host" mmft-agent identity --dir "$state"
done

# start_run HOST starts `mmft-agent run` as a service manager would, logging
# to the spool.
start_run() {
  docker compose exec -d -T "$1" sh -c "exec mmft-agent run --dir $state >>$spool/run.log 2>&1"
}
# count HOST EVENT counts an event in the agent's run log.
count() {
  in_lab "$1" grep -c "\"event\":\"$2\"" "$spool/run.log" 2>/dev/null || true
}
# wait_event HOST EVENT N SECONDS waits for the event to be logged N times.
wait_event() {
  echo "Waiting up to $4 seconds for $1 to log $2 ($3)..."
  for _ in $(seq 1 "$4"); do
    if [ "$(count "$1" "$2")" -ge "$3" ]; then
      pass "$label"
      return 0
    fi
    sleep 1
  done
  fail "$label"
  in_lab "$1" cat "$spool/run.log" || true
}
sql() { in_lab postgres psql -tA -U mmft -d mmft -c "$1"; }
# seen_after NAME TIME checks the orchestrator saw the agent after TIME, a
# Postgres timestamp.
seen_after() {
  n=$(sql "SELECT count(*) FROM agents a JOIN agent_presence p ON p.agent_id = a.id
           WHERE a.name = '$1' AND p.last_seen_at > '$2'::timestamptz")
  if [ "$n" = 1 ]; then pass "$label"; else fail "$label"; fi
}
db_now() { sql "SELECT now()"; }

for host in agent-a agent-b; do
  label="$host reaches the relay"
  expect_code 0 in_lab "$host" nc -z -w 2 relay 7445
done
label="the relay reports its certificate hash"
if [ "${#relay_fp}" = 64 ]; then pass "$label"; else fail "$label"; fi

echo "Starting both agents..."
mark=$(db_now)
for host in agent-a agent-b; do
  start_run "$host"
  label="$host connects"
  wait_event "$host" connected 1 30
done
# Heartbeats come every 30 seconds, so a fresh one proves the stream stayed up.
sleep 35
for host in agent-a agent-b; do
  label="the orchestrator sees $host through its heartbeats"
  seen_after "$host" "$(sql "SELECT now() - interval '35 seconds'")"
done

echo "Restarting agent-a..."
mark=$(db_now)
docker compose restart agent-a >/dev/null
start_run agent-a
label="agent-a reconnects after a restart"
wait_event agent-a connected 1 30
label="the orchestrator sees agent-a after its restart"
seen_after agent-a "$mark"

echo "Restarting the orchestrator..."
mark=$(db_now)
docker compose restart orchestrator >/dev/null
start_orchestrator "$lifetime"
# agent-a's log was reset by its restart, so it has one connection so far.
label="agent-a reconnects after the orchestrator restarts"
wait_event agent-a connected 2 90
label="agent-b reconnects after the orchestrator restarts"
wait_event agent-b connected 2 90
for host in agent-a agent-b; do
  label="the orchestrator sees $host after its restart"
  seen_after "$host" "$mark"
done

# C1: certificates last 2 minutes and renew after 1, so both agents renew,
# and they must still be connected once the first certificates expire.
for host in agent-a agent-b; do
  label="$host renews its connection certificate"
  wait_event "$host" renewed 1 150
done
expired_at=$((enrolled_at + 130))
now=$(date +%s)
if [ "$now" -lt "$expired_at" ]; then
  echo "Waiting $((expired_at - now)) seconds for the first certificates to expire..."
  sleep $((expired_at - now))
fi
mark=$(sql "SELECT now() - interval '35 seconds'")
sleep 35
for host in agent-a agent-b; do
  label="$host stays connected after its first certificate expired"
  seen_after "$host" "$mark"
  label="$host's saved certificate still works"
  expect_code 0 in_lab "$host" mmft-agent identity --dir "$state"
  label="$host never stopped"
  if [ "$(count "$host" stopped)" = 0 ]; then pass "$label"; else fail "$label"; fi
done

finish
