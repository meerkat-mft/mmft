#!/bin/sh
# Runs the checks CI runs, in the same order, and stops at the first failure.
# CI's SBOM job only produces an artifact, so it isn't repeated here.
# Without MMFT_TEST_DATABASE_URL it starts a throwaway Postgres in Docker for
# the database tests, and removes it afterwards.
set -eu
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

container=""
cleanup() {
  if [ -n "$container" ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
# A signal stops the script. Exiting runs the cleanup above.
trap 'exit 130' INT
trap 'exit 143' TERM

step "Build"
go build ./...

step "Build for Windows"
GOOS=windows go build ./...

if [ -z "${MMFT_TEST_DATABASE_URL:-}" ]; then
  step "Start a throwaway Postgres"
  container="mmft-check-$$"
  docker run -d --rm --name "$container" -e POSTGRES_DB=mmft -e POSTGRES_USER=mmft \
    -e POSTGRES_PASSWORD=check-only-not-a-secret -p 127.0.0.1::5432 postgres:18-alpine >/dev/null
  port=$(docker port "$container" 5432/tcp | head -n 1 | sed 's/.*://')
  printf 'Waiting for Postgres on port %s' "$port"
  tries=0
  # The host makes this wait for the TCP server, not the socket-only server
  # Postgres runs while it initializes a new database.
  until docker exec "$container" pg_isready -h 127.0.0.1 -U mmft -d mmft >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo
      echo "Postgres did not start" >&2
      exit 1
    fi
    printf '.'
    sleep 1
  done
  echo " ready"
  MMFT_TEST_DATABASE_URL="postgres://mmft:check-only-not-a-secret@127.0.0.1:$port/mmft?sslmode=disable"
  export MMFT_TEST_DATABASE_URL
fi

step "Test with the race detector"
go test -race ./...

# Tool versions come from ci.yml, so the two can't drift apart.
lint_version=$(sed -n 's/^ *version: *\(v[0-9][0-9.]*\) *$/\1/p' .github/workflows/ci.yml | head -n 1)
vuln_tool=$(sed -n 's/^ *- run: go run \(golang.org\/x\/vuln\/cmd\/govulncheck@v[0-9][0-9.]*\) .*$/\1/p' .github/workflows/ci.yml | head -n 1)
if [ -z "$lint_version" ] || [ -z "$vuln_tool" ]; then
  echo "Could not find the golangci-lint or govulncheck version in .github/workflows/ci.yml" >&2
  exit 1
fi
step "Lint with golangci-lint $lint_version"
go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$lint_version" run

step "Check the API definitions"
scripts/check-api.sh

step "Scan for known vulnerabilities with ${vuln_tool#*@}"
go run "$vuln_tool" ./...

printf '\nAll checks passed.\n'
