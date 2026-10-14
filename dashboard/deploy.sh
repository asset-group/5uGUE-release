#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Building static dashboard ==="
python3 "$SCRIPT_DIR/build_static.py"

echo "=== Deploying to Cloudflare Pages ==="
echo "CF_TOKEN_PREFIX=${CLOUDFLARE_API_TOKEN:0:25}..."
wrangler pages deploy "$SCRIPT_DIR/build" \
  --project-name "${CF_PAGES_PROJECT:?set CF_PAGES_PROJECT to your Cloudflare Pages project name}" \
  --branch main \
  --commit-dirty=true

echo "=== Dashboard deployed successfully ==="
