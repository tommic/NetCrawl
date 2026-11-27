#!/bin/sh
# netcrawl-agent-update: replaces netcrawl-agent with the version the
# NetCrawl server offers. Runs as root from netcrawl-agent-update.service,
# started by a timer (every 6 hours) or when the crawler asks for it (it
# creates /var/lib/netcrawl-agent/update-requested).
#
# Nothing the crawler writes is trusted: the trigger file only starts this
# script. The binary comes from the server in /etc/netcrawl-agent/update.conf
# (root-owned, written by the installer), over the pinned TLS key, and must
# match the SHA-256 and version from the server's manifest.
set -eu

# NETCRAWL_UPDATE_ROOT and SYSTEMCTL exist for the tests only; under
# systemd nothing but root can set them.
ROOT=${NETCRAWL_UPDATE_ROOT:-}
SYSTEMCTL=${SYSTEMCTL:-systemctl}
CONF=$ROOT/etc/netcrawl-agent/update.conf
AGENT_CONF=$ROOT/etc/netcrawl-agent/agent.json
BIN=$ROOT/usr/local/bin/netcrawl-agent
TRIGGER=$ROOT/var/lib/netcrawl-agent/update-requested

log() { printf 'netcrawl-agent-update: %s\n' "$*"; }
die() { log "error: $*" >&2; exit 1; }

# Consumed right away: a failed update must not retrigger itself in a loop.
rm -f "$TRIGGER"

[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || die "must run as root"
[ -f "$CONF" ] || die "$CONF missing (reinstall the crawler)"
if grep -Eq '"auto_update"[[:space:]]*:[[:space:]]*false' "$AGENT_CONF" 2>/dev/null; then
  log "auto_update is off in $AGENT_CONF, nothing to do"
  exit 0
fi

# update.conf holds two lines, SERVER_URL=... and TLS_PIN=...; read, not sourced.
# Host characters only ("]" first inside the brackets, for IPv6 literals).
SERVER_URL=$(sed -n 's/^SERVER_URL=\(https\{0,1\}:\/\/[][A-Za-z0-9.:-]\{1,\}\)$/\1/p' "$CONF" | head -n 1)
TLS_PIN=$(sed -n 's/^TLS_PIN=\(sha256\/\/[A-Za-z0-9+\/=]*\)$/\1/p' "$CONF" | head -n 1)
[ -n "$SERVER_URL" ] || die "no valid SERVER_URL in $CONF"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

fetch() {
  if [ -n "$TLS_PIN" ]; then
    curl -fsS --retry 3 --max-time 300 -k --pinnedpubkey "$TLS_PIN" "$@"
  else
    curl -fsS --retry 3 --max-time 300 "$@"
  fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch -o "$TMP/latest" "$SERVER_URL/install/agent/latest" || die "cannot reach $SERVER_URL"
WANT=$(sed -n 's/^version \([0-9A-Za-z.+-]\{1,40\}\)$/\1/p' "$TMP/latest" | head -n 1)
SUM=$(sed -n "s/^linux-$ARCH \([0-9a-f]\{64\}\)\$/\1/p" "$TMP/latest" | head -n 1)
[ -n "$WANT" ] && [ -n "$SUM" ] || die "the server offers no netcrawl-agent for linux-$ARCH"

HAVE=$("$BIN" --version 2>/dev/null || echo none)
if [ "$HAVE" = "$WANT" ]; then
  log "up to date ($HAVE)"
  exit 0
fi

log "updating $HAVE -> $WANT"
fetch -o "$TMP/netcrawl-agent" "$SERVER_URL/install/agent/linux-$ARCH" || die "download failed"
echo "$SUM  $TMP/netcrawl-agent" | sha256sum -c - >/dev/null 2>&1 || die "checksum mismatch, keeping $HAVE"
chmod 0755 "$TMP/netcrawl-agent"
NEW=$("$TMP/netcrawl-agent" --version 2>/dev/null || true)
[ "$NEW" = "$WANT" ] || die "downloaded binary reports version '$NEW', expected '$WANT'; keeping $HAVE"

# Replace atomically, then restart the crawler with the new binary.
install -m 0755 "$TMP/netcrawl-agent" "$BIN.new"
mv -f "$BIN.new" "$BIN"
"$SYSTEMCTL" restart netcrawl-agent
log "updated to $WANT"
