#!/bin/sh
# Removes netcrawl-agent installed by the NetCrawl installer.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "please run as root" >&2; exit 1; }
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now netcrawl-agent 2>/dev/null || true
  rm -rf /etc/systemd/system/netcrawl-agent.service /etc/systemd/system/netcrawl-agent.service.d
  systemctl daemon-reload 2>/dev/null || true
fi
rm -f /usr/local/bin/netcrawl-agent
rm -rf /etc/netcrawl-agent /var/lib/netcrawl-agent
if getent passwd netcrawl >/dev/null 2>&1; then
  userdel netcrawl 2>/dev/null || true
fi
echo "netcrawl-agent removed. Disable or delete the crawler in the web UI as well."
