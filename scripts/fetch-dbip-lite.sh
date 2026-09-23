#!/usr/bin/env bash
# Fetch the DB-IP Lite City and ASN databases (MaxMind DB format) into a
# directory the sentinel mounts at /geoip.
#
#   scripts/fetch-dbip-lite.sh /bulk0/mcl-sentinel-geoip           # this month
#   scripts/fetch-dbip-lite.sh /bulk0/mcl-sentinel-geoip 2026-09   # a given month
#
# DB-IP publishes a Lite release each month at
#   https://download.db-ip.com/free/dbip-{city,asn}-lite-YYYY-MM.mmdb.gz
# With no month given, this tries the current UTC month and falls back to the
# previous one, because the new release appears some time after the 1st.
#
# The data is CC BY 4.0: "IP Geolocation by DB-IP" (https://db-ip.com). Anything
# that shows it credits DB-IP.
#
# Each file is downloaded next to its target, checked to BE a MaxMind DB (a
# 404 page or a truncated gzip is not), and only then renamed into place, so a
# failed run leaves the previous databases untouched. The sentinel loads the
# files at boot: restart it to pick up a new month.

set -euo pipefail

DEST="${1:?usage: $0 DEST_DIR [YYYY-MM]}"
BASE="https://download.db-ip.com/free"
MONTH="${2:-}"

[ -d "$DEST" ] || { echo "no such directory: $DEST" >&2; exit 1; }
[ -z "$MONTH" ] || [[ "$MONTH" =~ ^[0-9]{4}-[0-9]{2}$ ]] || { echo "month must be YYYY-MM, got: $MONTH" >&2; exit 1; }

published() {
    curl -fsI "$BASE/dbip-city-lite-$1.mmdb.gz" >/dev/null 2>&1
}

if [ -z "$MONTH" ]; then
    THIS=$(date -u +%Y-%m)
    LAST=$(date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m)
    if published "$THIS"; then MONTH="$THIS"
    elif published "$LAST"; then MONTH="$LAST"
    else echo "no DB-IP Lite release found for $THIS or $LAST" >&2; exit 1
    fi
fi

fetch() {
    local kind="$1" target="$DEST/dbip-$1-lite.mmdb" partial
    partial=$(mktemp "$DEST/.dbip-$kind-XXXXXX")
    trap 'rm -f "$partial"' RETURN
    curl -fsS "$BASE/dbip-$kind-lite-$MONTH.mmdb.gz" | gunzip -c > "$partial"
    # Every MaxMind DB ends its data section with this metadata marker.
    if ! LC_ALL=C grep -aq $'\xab\xcd\xefMaxMind.com' "$partial"; then
        echo "dbip-$kind-lite-$MONTH is not a MaxMind DB; keeping the old file" >&2
        return 1
    fi
    chmod 0644 "$partial"
    mv -f "$partial" "$target"
    echo "$target <- dbip-$kind-lite-$MONTH ($(stat -c %s "$target") bytes)"
}

fetch city
fetch asn
