#!/usr/bin/env bash
# Build the kseal docs site from the canonical Markdown.
#
# The site never copies doc bodies. It assembles a staging tree (.staging/) of
# SYMLINKS that mirrors the repo layout, so:
#   - every page is the real file in docs/ (or a root doc), and
#   - relative cross-links like ../ARCHITECTURE.md resolve at build time.
#
# Usage:
#   ./build.sh            # build static HTML into ./build
#   ./build.sh serve      # live-reload dev server on http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v mkdocs >/dev/null 2>&1; then
  echo "mkdocs not found. Install it first:  pip install -r requirements.txt" >&2
  exit 1
fi

# Reassemble the staging tree from scratch so deletions in docs/ are reflected.
rm -rf .staging
mkdir -p .staging/docs

# Landing page + other site-owned Markdown (the only Markdown this dir authors).
ln -s ../index.md .staging/index.md
ln -s ../secure-your-app.md .staging/secure-your-app.md

# Site-owned static assets (custom theme CSS, images).
ln -s ../css .staging/css

# Root docs that docs/*.md cross-link to via ../NAME.md.
for f in PROPOSAL.md ARCHITECTURE.md PROGRESS.md; do
  ln -s "../../$f" ".staging/$f"
done
# The root README is staged under a distinct name: MkDocs treats README.md as an
# index page, which would collide with the site landing index.md.
ln -s ../../README.md .staging/project-overview.md

# Every docs/*.md, preserving the docs/ path so intra-docs links resolve.
# Skip docs/README.md — it is the folder's scaffold index, not site content.
for f in ../docs/*.md; do
  base="$(basename "$f")"
  [[ "$base" == "README.md" ]] && continue
  ln -s "../../../docs/$base" ".staging/docs/$base"
done

if [[ "${1:-build}" == "serve" ]]; then
  exec mkdocs serve
fi

mkdocs build
echo "Built site -> $(pwd)/build (open build/index.html)"
