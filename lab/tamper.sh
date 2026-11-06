#!/bin/sh
# Failure tests T1 to T3: a hostile test relay alters, truncates, and swaps
# sealed files between agent-a and agent-b. Each time the destination must
# refuse the file, decrypt nothing, place nothing in its inbox, and report a
# stable error code, while the source is told the delivery went through.
set -eu
cd "$(dirname "$0")"

# The test relay plays a hostile relay, and reads its mode from this file
# before each delivery.
relay_cmd="env MMFT_RELAY_TAMPER=on mmft-testrelay"
. ./lib.sh
trap cleanup EXIT
setup_lab

work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT

enroll_both "$work"
run_with_boxes

# Every file has the same size, so a swapped sealed file has the size the
# manifest names and only the hash check can catch it.
n=0
new_file() {
  n=$((n + 1))
  name="file-$n.txt"
  for i in $(seq 1 2000); do echo "file $n, line $i"; done | head -c 60000 >"$work/$name"
  put agent-a "$outbox/$name" <"$work/$name"
}
set_mode() { printf '%s' "$1" | put relay "$relay/tamper-mode"; }
# status_of and error_of read the run's status and the delivery's error code.
status_of() { field status <"$work/run.json" | head -n 1; }
error_of() { field error_code <"$work/run.json"; }

# check_refused ID CODE checks that the delivery failed with CODE and
# that agent-b decrypted and placed nothing.
check_refused() {
  label="$1: the delivery fails with $2"
  if [ "$(status_of)" = failed ] && [ "$(error_of)" = "$2" ]; then pass "$label"; else fail "$label"; cat "$work/run.json"; fi
  label="$1: agent-b's inbox has no file and no partial file"
  if [ "$(in_lab agent-b ls -A "$inbox" | grep -c -v -x -F "$first")" = 0 ]; then pass "$label"; else fail "$label"; fi
  for host in agent-a agent-b; do
    label="$1: $host's spool is empty"
    if [ -z "$(in_lab "$host" ls -A "$spool/sealed")" ]; then pass "$label"; else fail "$label"; fi
  done
}

echo "A clean delivery first, which the swap test replays later..."
set_mode pass
new_file
first=$name
label="an unchanged file arrives"
if send_file "$name" "$work/run.json" && [ "$(status_of)" = succeeded ]; then pass "$label"; else fail "$label"; cat "$work/run.json"; fi

echo "T1: the relay flips one byte of the sealed file..."
set_mode flip
new_file
send_file "$name" "$work/run.json" || true
check_refused T1 hash_mismatch

echo "T2: the relay drops the end of the sealed file..."
set_mode truncate
new_file
send_file "$name" "$work/run.json" || true
# The destination knows the size from the signed manifest, so it refuses a
# short file before any hash check or decryption.
check_refused T2 relay_failed

echo "T3: the relay sends the sealed file of the previous delivery instead..."
set_mode swap
new_file
send_file "$name" "$work/run.json" || true
check_refused T3 hash_mismatch

# A control, so a relay that silently forwarded everything can't pass.
for mode in flip truncate swap; do
  label="the relay really used $mode"
  if in_lab relay grep -q "\"mode\":\"$mode\"" "$relay/relay.log"; then pass "$label"; else fail "$label"; fi
done

finish
