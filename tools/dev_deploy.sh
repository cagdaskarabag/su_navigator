#!/usr/bin/env bash
# Copy the app into a local Splunk Enterprise instance for development.
# Modular-input discovery does not follow a symlinked app directory, so the
# app is copied (local/ and the KV Store data are preserved).
set -euo pipefail
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/sunavigator"
DEST="$SPLUNK_HOME/etc/apps/sunavigator"

if [ -L "$DEST" ]; then rm "$DEST"; fi
mkdir -p "$DEST"
rsync -a --delete --exclude local/ --exclude '__pycache__/' --exclude '*.pyc' "$SRC/" "$DEST/"
if [ "${1:-}" = "--restart" ]; then
  "$SPLUNK_HOME/bin/splunk" restart
else
  echo "Deployed to $DEST. Restart Splunk (or use --restart) to load configuration changes."
fi
