#!/bin/sh
# Starts the lab and checks the conditions that later failure tests rely on.
set -eu
cd "$(dirname "$0")"

fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
expect_ok() { if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi; }
expect_fail() { if "$@" >/dev/null 2>&1; then fail "$label"; else pass "$label"; fi; }
in_lab() { docker compose exec -T "$@"; }

cleanup() { docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose up --build --detach --wait --wait-timeout 120

for service in orchestrator relay agent-a agent-b; do
  label="$service runs its version command"
  expect_ok in_lab "$service" mmft version
done

label="agent-a resolves the orchestrator"
expect_ok in_lab agent-a getent hosts orchestrator
label="agent-a resolves the relay"
expect_ok in_lab agent-a getent hosts relay
label="agent-b resolves the relay"
expect_ok in_lab agent-b getent hosts relay
label="agent-a cannot resolve agent-b"
expect_fail in_lab agent-a getent hosts agent-b
label="agent-b cannot resolve agent-a"
expect_fail in_lab agent-b getent hosts agent-a
label="agent-a cannot resolve postgres"
expect_fail in_lab agent-a getent hosts postgres
# TCP checks with a real listener, so a failure means blocked and not missing.
docker compose exec -d -T relay nc -lk -p 9000 -e /bin/true
docker compose exec -d -T agent-b nc -lk -p 9000 -e /bin/true
docker compose exec -d -T orchestrator nc -lk -p 9000 -e /bin/true
sleep 1
agent_b_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mmft-lab-agent-b-1)
label="agent-a can open a connection to the relay"
expect_ok in_lab agent-a nc -z -w 2 relay 9000
label="agent-b can open a connection to the orchestrator"
expect_ok in_lab agent-b nc -z -w 2 orchestrator 9000
label="agent-a cannot connect to agent-b by IP address ($agent_b_ip)"
expect_fail in_lab agent-a nc -z -w 2 "$agent_b_ip" 9000
label="agent-a cannot connect to the internet"
expect_fail in_lab agent-a nc -z -w 3 1.1.1.1 443

label="agents run as an unprivileged user"
if [ "$(in_lab agent-a id -u)" = "10001" ]; then pass "$label"; else fail "$label"; fi
label="agent root filesystem is read-only"
expect_fail in_lab agent-a touch /usr/local/bin/tampered
label="agent spool is writable"
expect_ok in_lab agent-a touch /var/lib/mmft/spool/ok
label="full spool fails rather than growing"
expect_fail in_lab agent-a dd if=/dev/zero of=/var/lib/mmft/spool/fill bs=1M count=32

docker compose kill agent-a >/dev/null 2>&1
label="killed agent is down"
expect_fail in_lab agent-a true
docker compose start agent-a >/dev/null 2>&1
label="killed agent restarts"
expect_ok in_lab agent-a true

net="mmft-lab_site-a"
docker network disconnect "$net" mmft-lab-relay-1
label="agent-a loses the relay when its network drops"
expect_fail in_lab agent-a getent hosts relay
docker network connect "$net" mmft-lab-relay-1
label="agent-a regains the relay"
expect_ok in_lab agent-a getent hosts relay

if [ "$fails" -ne 0 ]; then
  echo "$fails checks failed"
  exit 1
fi
echo "All checks passed"
