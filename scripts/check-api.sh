#!/bin/sh
# Lints the API definitions and fails if generated code is out of date. Run with
# --write to regenerate the code instead of failing.
set -eu
cd "$(dirname "$0")/.."

buf="go run github.com/bufbuild/buf/cmd/buf@v1.75.0"
# Redocly is installed from tools/package-lock.json, which pins its exact
# version and hash. Install scripts never run.
redocly="tools/node_modules/.bin/redocly"

(cd api && $buf lint)
npm ci --prefix tools --ignore-scripts --no-audit --no-fund --loglevel=error
$redocly lint api/openapi.yaml

# The flow version schema must accept every valid fixture and reject every
# invalid one, except the rules a schema can't express, which only the Go
# package internal/flow checks: tree shape, fields that must agree with each
# other, and repeated JSON fields.
ajv="tools/node_modules/.bin/ajv validate --spec=draft2020 --strict=true -s api/flow-version.schema.json"
go_only="agents-mismatch agents-unsorted destination-after-destination destination-on-source-agent
  loop repeated-card-id repeated-field-in-card same-destination-twice unknown-parent"
echo "Checking the flow retirement schema"
tools/node_modules/.bin/ajv compile --spec=draft2020 --strict=true -s api/flow-retirement.schema.json
echo "Checking the flow version schema against the fixtures"
$ajv -d "internal/flow/testdata/valid/*.json"
for f in internal/flow/testdata/invalid/*.json; do
  name=$(basename "$f" .json)
  case " $(echo $go_only) " in *" $name "*) continue ;; esac
  if $ajv -d "$f" >/dev/null 2>&1; then
    echo "The flow version schema accepts $f" >&2
    exit 1
  fi
  echo "$f rejected by the schema"
done

rm -rf gen
(cd api && $buf generate)

if [ "${1:-}" != "--write" ]; then
  if [ -n "$(git status --porcelain gen)" ]; then
    git status --short gen
    echo "Generated code is out of date. Run scripts/check-api.sh --write" >&2
    exit 1
  fi
fi
