#!/usr/bin/env bash
# Build dist/splunk_use_case_manager-<version>.tar.gz for installation or AppInspect.
# Excludes local configuration, user metadata and Python bytecode.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP=splunk_use_case_manager
VERSION="$(sed -n 's/^version *= *//p' "$ROOT/$APP/default/app.conf" | head -1)"
OUT="$ROOT/dist/$APP-$VERSION.tar.gz"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$ROOT/dist"
rsync -a --exclude 'local/' --exclude 'local.meta' --exclude '__pycache__/' --exclude '*.pyc' \
      --exclude '.DS_Store' "$ROOT/$APP/" "$STAGE/$APP/"
find "$STAGE/$APP" -type d -exec chmod 755 {} +
find "$STAGE/$APP" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/$APP"/bin/*.py
tar -C "$STAGE" --owner=0 --group=0 -czf "$OUT" "$APP"
echo "$OUT"
