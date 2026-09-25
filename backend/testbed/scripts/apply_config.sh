#!/usr/bin/env bash
# Copies a named ipsec.conf variant (+ the shared PSK secrets file) into
# configs/active/, which docker-compose.yml bind-mounts into alice and bob.
#
# Usage: ./apply_config.sh tunnel_aesgcm256_dh19_pfson_ipv4
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <config-name>" >&2
    exit 1
fi

CONFIG_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$TESTBED_DIR/configs/${CONFIG_NAME}.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "no such config: $CONFIG_FILE" >&2
    echo "available configs:" >&2
    ls "$TESTBED_DIR"/configs/*.conf | xargs -n1 basename >&2
    exit 1
fi

mkdir -p "$TESTBED_DIR/configs/active"
cp "$CONFIG_FILE" "$TESTBED_DIR/configs/active/ipsec.conf"
cp "$TESTBED_DIR/configs/common/ipsec.secrets" "$TESTBED_DIR/configs/active/ipsec.secrets"
chmod 600 "$TESTBED_DIR/configs/active/ipsec.secrets"

echo "Applied ${CONFIG_NAME}."
echo "Restart the daemons to pick it up:"
echo "  docker compose -f $TESTBED_DIR/docker-compose.yml restart alice bob"
