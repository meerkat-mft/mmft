#!/bin/sh
# Demonstrates M1 with one command: it runs every lab script that applies to
# M1, in order, and reports each result. Each script starts its own lab and
# removes it. It takes about five minutes, most of them for the certificate
# renewal in connect.sh.
#
#   lab/m1.sh
set -u
cd "$(dirname "$0")"

scripts="smoke enroll connect deliver tamper"
failed=""
for s in $scripts; do
  echo
  echo "=== $s.sh ==="
  start=$(date +%s)
  if ./"$s".sh; then
    echo "=== $s.sh passed in $(($(date +%s) - start)) seconds ==="
  else
    echo "=== $s.sh FAILED ==="
    failed="$failed $s"
  fi
done

echo
echo "M1 lab results:"
for s in $scripts; do
  case " $failed " in
    *" $s "*) echo "  FAIL  $s.sh" ;;
    *) echo "  PASS  $s.sh" ;;
  esac
done
if [ -n "$failed" ]; then
  echo "M1 is not demonstrated: fix$failed"
  exit 1
fi
echo "M1 is demonstrated: two agents enroll, stay connected and renew, move a file"
echo "through the blind relay with neither the relay nor the orchestrator seeing it,"
echo "and refuse every altered, truncated, or swapped sealed file."
