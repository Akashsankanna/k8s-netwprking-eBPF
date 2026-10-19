#!/usr/bin/env bash
# Suggested runtime from docs/ARCHITECTURE.md.
# Phase 1 and Phase 2 cannot share a NIC (one XDP program per interface).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE_FILTER="${IFACE_FILTER:-eth0}"
IFACE_MONITOR="${IFACE_MONITOR:-eth1}"
LISTEN="${LISTEN:-:8080}"

need() {
  if [[ ! -x "$1" ]]; then
    echo "missing $1 — run 'make userspace' (and 'make bpf' on Linux) from $ROOT" >&2
    exit 1
  fi
}

need "$ROOT/phase1/phase1-loader"
need "$ROOT/phase3/phase3-rules-manager"
need "$ROOT/phase4/phase4-api-server"

if [[ ! -f "$ROOT/phase1/phase1_packet_filter.o" ]]; then
  echo "missing phase1_packet_filter.o — run 'make bpf' on Linux 5.8+" >&2
  exit 1
fi

echo "Phase 1 filter on ${IFACE_FILTER} (creates pinned maps)"
sudo "$ROOT/phase1/phase1-loader" -interface "$IFACE_FILTER" &
P1=$!
sleep 1

echo "Phase 3 rules -> /sys/fs/bpf/firewall_rules"
sudo "$ROOT/phase3/phase3-rules-manager" -rules "$ROOT/phase3/example_rules.json" &
P3=$!
sleep 1

echo "Phase 4 API on ${LISTEN} (file-only until maps exist; maps should be up)"
"$ROOT/phase4/phase4-api-server" -listen "$LISTEN" -rules-file "$ROOT/phase3/example_rules.json" -seed &
P4=$!

P2=""
if [[ -x "$ROOT/phase2/phase2-collector" && -f "$ROOT/phase2/phase2_ringbuf_events.o" ]]; then
  if ip link show "$IFACE_MONITOR" >/dev/null 2>&1; then
    echo "Phase 2 monitor on ${IFACE_MONITOR} (optional; different NIC from filter)"
    sudo "$ROOT/phase2/phase2-collector" -interface "$IFACE_MONITOR" &
    P2=$!
  else
    echo "Skip Phase 2: interface ${IFACE_MONITOR} not found (set IFACE_MONITOR)"
  fi
fi

cleanup() {
  echo "Stopping phases..."
  kill "$P4" 2>/dev/null || true
  sudo kill "$P3" 2>/dev/null || true
  sudo kill "$P1" 2>/dev/null || true
  if [[ -n "$P2" ]]; then sudo kill "$P2" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

echo "Running. Ctrl+C to detach XDP (pins under /sys/fs/bpf remain until sudo rm)."
wait
