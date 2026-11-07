#!/bin/sh
# Regenerates tokens.css from ../DESIGN.md, so the prototype never holds its
# own copy of a colour, spacing, or radius. Run it after changing DESIGN.md.
set -eu
cd "$(dirname "$0")"
{
  echo "/* Generated from design/DESIGN.md by tokens.sh. Do not edit. */"
  npx --yes @google/design.md@0.4.0 export --format css-vars ../DESIGN.md
} >tokens.css
echo "Wrote tokens.css"
