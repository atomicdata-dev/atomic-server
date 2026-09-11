#!/usr/bin/env sh
# Run from cron, launchd or a systemd timer. Archives are retained indefinitely.
set -eu
: "${ATOMIC_BACKUP_TOKEN_FILE:?Set the path to the backup.token in the server config directory}"
exec "${ATOMIC_SERVER_BIN:-atomic-server}" backup \
  --server "${ATOMIC_BACKUP_SERVER:-http://127.0.0.1:9883}" \
  --token-file "$ATOMIC_BACKUP_TOKEN_FILE"
