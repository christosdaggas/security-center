#!/usr/bin/env bash
# Download the free DB-IP Lite Country database for offline GeoIP lookups.
#
# DB-IP Lite is licensed CC BY 4.0 (attribution required, redistribution allowed).
# The database is refreshed monthly; the URL encodes the current year-month.
#
# Usage: sudo scripts/fetch-geoip.sh [target-dir]
#   target-dir defaults to /usr/share/GeoIP
set -euo pipefail

TARGET_DIR="${1:-/usr/share/GeoIP}"
YM="$(date +%Y-%m)"
URL="https://download.db-ip.com/free/dbip-country-lite-${YM}.mmdb.gz"
DEST="${TARGET_DIR}/dbip-country-lite.mmdb"

for tool in curl gzip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' is required" >&2; exit 1; }
done

echo "Downloading DB-IP Lite Country (${YM}) ..."
mkdir -p "$TARGET_DIR"
tmp="$(mktemp)"
trap 'rm -f "$tmp" "$tmp.gz"' EXIT

if ! curl -fSL "$URL" -o "$tmp.gz"; then
    echo "error: download failed. Check https://db-ip.com/db/download/ip-to-country-lite" >&2
    exit 1
fi

gzip -dc "$tmp.gz" > "$tmp"
install -m 0644 "$tmp" "$DEST"

echo "Installed: $DEST"
echo "Security Center will show country flags on the next Network Exposure scan."
echo "Data © DB-IP (https://db-ip.com), licensed CC BY 4.0."
