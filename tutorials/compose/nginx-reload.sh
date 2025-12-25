#!/usr/bin/env sh
set -ex
set -uo pipefail

# SETTING: Location of your Docker Compose setup.
# The default is to use the location of this script. Change this if you moved
# it to a different location (e.g. /usr/local/bin/)
SCRIPT_PATH=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)/$(basename "$0")

SERVICE=webserver
COMPOSE_DIR="$SCRIPT_PATH"
COMPOSE_FILE="$SCRIPT_PATH/compose.yaml"

docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" exec "$SERVICE" nginx -t
docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" exec "$SERVICE" nginx -s reload
