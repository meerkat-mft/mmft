#!/bin/sh
# Lints the API definitions and fails if generated code is out of date. Run with
# --write to regenerate the code instead of failing.
set -eu
cd "$(dirname "$0")/.."

buf="go run github.com/bufbuild/buf/cmd/buf@v1.75.0"
redocly="npx --yes @redocly/cli@2.72.1"

(cd api && $buf lint)
$redocly lint api/openapi.yaml

rm -rf gen
(cd api && $buf generate)

if [ "${1:-}" != "--write" ]; then
  if [ -n "$(git status --porcelain gen)" ]; then
    git status --short gen
    echo "Generated code is out of date. Run scripts/check-api.sh --write" >&2
    exit 1
  fi
fi
