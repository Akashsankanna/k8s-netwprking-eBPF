# eBPF Firewall — System Design

The up-to-date structure, gap list, and recommended layout are in
[ARCHITECTURE.md](ARCHITECTURE.md). This file is the original design note
(map layouts and matching semantics).

## 1. Overview

This is a 4-phase, modular firewall built on eBPF/XDP. Each phase is an
independent binary that can be built and run on its own; together they
form a full data path + observability + control plane stack.

```
┌─────────────────────────────────────────────────┐
│ Phase 4: REST API Server (Go)                    │  ← Management Interface
│ Endpoints: GET/POST/PUT/DELETE rules              │
├─────────────────────────────────────────────────┤
│ Phase 3: Rules Manager (Go)                       │  ← Policy Engine
│ Loads, validates, manages rules                   │
├─────────────────────────────────────────────────┤
│ Phase 2: Event Collector (Go + eBPF)              │  ← Observability
│ Real-time packet monitoring                       │
├─────────────────────────────────────────────────┤
│ Phase 1: Packet Filter (Go + eBPF XDP)            │  ← Data Path
│ Fast kernel-space filtering                       │
├─────────────────────────────────────────────────┤
│ Linux Kernel 5.8+                                 │  ← Foundation
└─────────────────────────────────────────────────┘
```

## 2. How the phases connect

```
example_rules.json
      │
      ▼
phase3_rules_manager.go ──writes──▶ /sys/fs/bpf/firewall_rules (pinned map)
                                              │
                                              ▼
                              phase1_packet_filter.c (XDP)
                              reads rules_map, writes stats_map
                                              │
                                    (independent hook, same NIC)
                                              ▼
                              phase2_ringbuf_events.c (XDP)
                              streams packet_event structs via ring buffer
                                              │
                                              ▼
                              phase2_collector.go (reads ring buffer,
                                                    prints live events + flow counts)

phase4_api_server.go ──reads/writes──▶ /sys/fs/bpf/firewall_rules
                      ──reads────────▶ /sys/fs/bpf/firewall_stats
                      ──persists to──▶ example_rules.json (or -rules-file path)
```

Phase 1 and Phase 2 are designed to be a filter + observer pair, but Linux
only allows one active XDP program per interface. In practice, Phase 1 and
Phase 2 must not both attach to the same NIC at the same time; Phase 2 should
run on a second interface, or Phase 1 should be stopped before starting the
monitor. The filter and monitor remain conceptually separate, but the kernel
runtime model is single-XDP-per-interface.

Phase 3 and Phase 4 both write into the *same* pinned `firewall_rules`
map that Phase 1 reads, so either one (or both) can manage rules — Phase 3
is intended for file-driven/GitOps-style rule management with hot-reload,
Phase 4 is for interactive/programmatic control via HTTP.

## 3. Shared data structures

The rule key/value structs **must be byte-identical** between the C
(kernel-space) and Go (userspace) sides, since they're the same bytes in
the same BPF map. This project deliberately avoids `__attribute__((packed))`
on the C struct so that natural compiler alignment is used on both sides:

```c
// C side (phase1_packet_filter.c) — NOT packed
struct rule_key {
    __u8  protocol;   // offset 0
    __u16 dst_port;   // offset 2 (1 byte compiler padding after protocol)
};                     // sizeof == 4
```

```go
// Go side (phase3, phase4) — mirrors the compiler-inserted padding explicitly
type ruleKey struct {
    Protocol uint8
    _        uint8   // padding, matches C compiler layout
    DstPort  uint16
}
```

If you ever change one side, change the other and re-verify with
`offsetof`/`unsafe.Sizeof`, or things will silently write into the wrong
map slot.

## 4. Rule matching semantics (Phase 1)

For each IPv4 packet:
1. Look up `{protocol, dst_port}` in `rules_map` (exact match).
2. If not found, look up `{protocol, 0}` (protocol-level wildcard).
3. If still not found, apply the **default policy**: drop ICMP, allow
   everything else.

`protocol` values: `1` = ICMP, `6` = TCP, `17` = UDP, `0` = wildcard/any.

## 5. Maps

| Map | Type | Pinned at | Written by | Read by |
|---|---|---|---|---|
| `firewall_rules` | `BPF_MAP_TYPE_HASH` | `/sys/fs/bpf/firewall_rules` | phase3, phase4 | phase1 (kernel), phase3, phase4 |
| `firewall_stats` | `BPF_MAP_TYPE_ARRAY` (4 counters) | `/sys/fs/bpf/firewall_stats` | phase1 (kernel) | phase1 (printer), phase4 |
| `events` (ring buffer) | `BPF_MAP_TYPE_RINGBUF` | not pinned (per-process) | phase2 (kernel) | phase2_collector.go |
| `flows` | `BPF_MAP_TYPE_LRU_HASH` | not pinned | phase2 (kernel) | phase2_collector.go |

## 6. Why generic (SKB) XDP mode by default

The Go loaders attach with `link.XDPGenericMode`, which works on any NIC
driver without special support, at some cost to throughput versus native
driver mode. For production, switch to `link.XDPDriverMode` (or add
`-driver-mode` flag) once you've confirmed your NIC driver supports
native XDP (`ip link show` will list `xdpdrv` support, or check
`ethtool -i <iface>`).

## 7. Security note on Phase 4

The REST API has **no built-in authentication**. It can create/modify/
delete firewall rules over HTTP. Do not expose `phase4-api-server`
directly to an untrusted network — put it behind a reverse proxy with
TLS + auth (mTLS, an API key header, or an OAuth-aware proxy), or bind it
to `127.0.0.1`/a private interface only.
