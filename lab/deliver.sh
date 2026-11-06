#!/bin/sh
# Enrolls both lab agents, runs them with an outbox and inbox, and moves one
# file from agent-a to agent-b with `mmft delivery send`, through the test
# relay. It checks that the file arrives unchanged with both signed statements,
# that the relay saw only sealed bytes, that the orchestrator holds none of the
# file, and that both spools are empty afterwards.
set -eu
cd "$(dirname "$0")"

# The test relay is the real relay plus a copy of every byte it forwards.
relay_cmd=mmft-testrelay
. ./lib.sh
trap cleanup EXIT
setup_lab

work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT

echo "Enrolling and approving both agents..."
for host in agent-a agent-b; do
  token "$host" | field token | put "$host" "$spool/token"
  install "$host" "$host" "$state" >/dev/null
  in_lab "$host" mmft-agent fingerprint --dir "$state" --json >>"$work/fingerprints.json"
done
approve "$work/fingerprints.json" >/dev/null

echo "Starting both agents with an outbox and inbox..."
for host in agent-a agent-b; do
  in_lab "$host" mkdir -p "$spool/sealed"
  docker compose exec -d -T "$host" sh -c \
    "exec mmft-agent run --dir $state --outbox $outbox --inbox $inbox --spool $spool/sealed >>$spool/run.log 2>&1"
done

# A file whose lines all carry a random marker, so any copy of the plaintext is
# easy to find.
marker=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
name="report-$marker.txt"
for i in $(seq 1 4000); do echo "line $i of the file with marker $marker"; done >"$work/source"
put agent-a "$outbox/$name" <"$work/source"
source_sum=$(sha256sum <"$work/source" | cut -d' ' -f1)
# A positive control, so the checks below can tell a missing marker from a
# search that can't find anything.
label="the marker is found in the source file"
if in_lab agent-a grep -q -F "$marker" "$outbox/$name"; then pass "$label"; else fail "$label"; fi

echo "Sending $name from agent-a to agent-b..."
label="mmft delivery send --wait succeeds"
send() {
  in_lab admin mmft delivery send --api orchestrator:7444 --ca-fingerprint "$ca_fp" --token-file "$admin/api-token" \
    --workspace lab --from agent-a --to agent-b --file "$name" --wait --timeout 2m
}
# The agents may still be connecting, which the API refuses with 409.
ok=
for _ in $(seq 1 30); do
  if send >"$work/run.json" 2>"$work/send.err"; then ok=1; break; fi
  grep -q 409 "$work/send.err" || break
  sleep 1
done
if [ -n "$ok" ]; then pass "$label"; else fail "$label"; cat "$work/send.err" "$work/run.json"; fi

label="the run succeeded"
if grep -q '"status": "succeeded"' "$work/run.json"; then pass "$label"; else fail "$label"; fi
label="the delivery holds both signed statements"
if grep -q '"evidence": "verified"' "$work/run.json"; then pass "$label"; else fail "$label"; fi

label="agent-b's inbox holds the same bytes"
dest_sum=$(in_lab agent-b sha256sum "$inbox/$name" 2>/dev/null | cut -d' ' -f1 || true)
if [ "$dest_sum" = "$source_sum" ]; then pass "$label"; else fail "$label"; fi

sealed_sum=$(field sealed_sha256 <"$work/run.json")
capture=$(in_lab relay sh -c "ls $relay/capture/*.sealed" 2>/dev/null | head -n 1 || true)
label="the relay forwarded exactly the sealed file in the manifest"
relay_sum=$(in_lab relay sha256sum "$capture" 2>/dev/null | cut -d' ' -f1 || true)
if [ -n "$sealed_sum" ] && [ "$relay_sum" = "$sealed_sum" ]; then pass "$label"; else fail "$label"; fi
label="the relay saw no plaintext"
if [ -n "$capture" ] && ! in_lab relay grep -q -F "$marker" "$capture"; then pass "$label"; else fail "$label"; fi
label="the relay's log names no file"
if ! in_lab relay grep -q -F "$marker" "$relay/relay.log"; then pass "$label"; else fail "$label"; fi

label="the orchestrator's database holds no file contents"
in_lab postgres pg_dump -U mmft -d mmft >"$work/db.sql"
# The file name is allowed in delivery_files only, and the name holds the
# marker, so count lines with the marker that aren't that one row.
tabbed=$(printf '\t%s' "$name")
contents=$(grep -F "$marker" "$work/db.sql" | grep -v -c -F "$tabbed" || true)
if [ "$contents" = 0 ]; then pass "$label"; else fail "$label"; fi
label="the file name is stored only in delivery_files"
if [ "$(grep -c -F "$name" "$work/db.sql" || true)" = 1 ]; then pass "$label"; else fail "$label"; fi
label="the orchestrator's CA directory holds nothing of the file"
if ! in_lab orchestrator grep -r -q -F "$marker" /var/lib/mmft/ca; then pass "$label"; else fail "$label"; fi

for host in agent-a agent-b; do
  label="$host's spool is empty"
  if [ -z "$(in_lab "$host" ls -A "$spool/sealed")" ]; then pass "$label"; else fail "$label"; fi
  label="$host's log names no file"
  if ! in_lab "$host" grep -q -F "$marker" "$spool/run.log"; then pass "$label"; else fail "$label"; fi
done

finish
