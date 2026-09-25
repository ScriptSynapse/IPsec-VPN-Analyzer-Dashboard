#!/usr/bin/env bash
# tcpdump wrapper: captures IKE control traffic + ESP on alice's public
# interface and writes a pcap named per the CLAUDE.md convention:
#   {mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap
#
# Usage: ./capture.sh tunnel_aesgcm256_dh19_pfson_ipv4 voip 30
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <config-name> <traffic-type> [duration-seconds]" >&2
    exit 1
fi

CONFIG_NAME="$1"
TRAFFIC_TYPE="$2"
DURATION="${3:-30}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M)"
OUT_NAME="${CONFIG_NAME}_${TRAFFIC_TYPE}_${TIMESTAMP}.pcap"
OUT_PATH="/pcaps/${OUT_NAME}"

# Don't assume the public-network interface is eth0 -- Docker Compose does
# not guarantee interface naming order across the networks a container is
# attached to (confirmed in practice: alice's public-network IP landed on
# eth1, not eth0, in one real run). Resolve it by IP instead.
IFACE="$(docker exec alice sh -c "ip -o addr show | awk '/inet 172\\.20\\.0\\./{print \$2}' | head -1")"
if [[ -z "$IFACE" ]]; then
    echo "could not find alice's public-network (172.20.0.0/24) interface -- is the testbed up?" >&2
    exit 1
fi

echo "Capturing on alice's public interface (${IFACE}) for ${DURATION}s -> ${OUT_NAME}"
docker exec alice timeout "${DURATION}" tcpdump -i "${IFACE}" -w "${OUT_PATH}" 'udp port 500 or udp port 4500 or esp'
echo "Wrote backend/data/pcaps/${OUT_NAME}"
