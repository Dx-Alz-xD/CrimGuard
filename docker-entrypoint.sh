#!/bin/sh
set -e

# Volumes on most hosts (Fly, Railway, plain Docker bind mounts) are mounted root-owned.
# Fix ownership while still root, then run the app as the unprivileged "node" user.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$(dirname "$RED_DB")"
  chown -R node:node "$(dirname "$RED_DB")"
  exec su-exec node "$@"
fi

exec "$@"
