#!/bin/bash
# Entrypoint of the worker image.
# Run as root (docker-compose "user: 0" with a reduced capability set), it
#   1. blocks every network connection of the scanner accounts (uid SAYTU_SCANNER_BASE_ID .. +999), the
#      scanners being started under those accounts by the worker (ScannerIsolation);
#   2. starts the worker without CAP_NET_ADMIN, so the rule cannot be removed afterwards.
# Run as any other user, it simply starts the worker (scanners then share the worker account).
# The outcome is written to /tmp/saytu-scanner-network ("blocked" or "open: reason") and shown in the UI.
set -u

status_file=/tmp/saytu-scanner-network
log_file=/tmp/saytu-iptables.log
first=${SAYTU_SCANNER_BASE_ID:-20000}
last=$((first + 999))
export XTABLES_LOCKFILE=/tmp/xtables.lock   # the root filesystem is read-only

block() { # $1: iptables or ip6tables
  local target
  for target in REJECT DROP; do
    if "$1" -w 5 -C OUTPUT -m owner --uid-owner "$first-$last" -j "$target" 2>/dev/null \
       || "$1" -w 5 -A OUTPUT -m owner --uid-owner "$first-$last" -j "$target" 2>>"$log_file"; then
      return 0
    fi
  done
  return 1
}

has_ipv6() { # a non-loopback IPv6 address in the container
  [ -r /proc/net/if_inet6 ] && awk '$6 != "lo" { found = 1 } END { exit !found }' /proc/net/if_inet6
}

if [ "$(id -u)" = "0" ]; then
  if ! command -v iptables > /dev/null; then
    status="open: iptables not installed in the image"
  elif ! block iptables; then
    status="open: firewall rule refused ($(tail -c 200 "$log_file" | tr '\n' ' '))"
  elif ! block ip6tables && has_ipv6; then
    status="open: IPv6 not filtered ($(tail -c 200 "$log_file" | tr '\n' ' '))"
  else
    status="blocked"
  fi
  printf '%s\n' "$status" > "$status_file"
  chmod 0644 "$status_file"
  echo "scanner network: $status"
  exec setpriv --bounding-set=-net_admin -- java -jar /app/app.jar "$@"
fi
exec java -jar /app/app.jar "$@"
