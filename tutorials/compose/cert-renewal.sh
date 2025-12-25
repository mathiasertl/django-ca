#!/usr/bin/env bash -ex
set -uo pipefail

# Get the location of this script. Change if you have stored to hook in a different location.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SERVICE=webserver
COMPOSE_DIR="$SCRIPT_DIR"
COMPOSE_FILE="$SCRIPT_DIR/compose.yaml"

docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" exec "$SERVICE" nginx -t
docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" exec "$SERVICE" nginx -s reload