# File Index

```
ebpf-firewall/
├── Makefile                          all / userspace / bpf / phase1–4 / verify / test / clean
├── scripts/run-topology.sh           Linux start order from the architecture plan
├── .gitignore                        object files, binaries, generated rules.json
├── docs/
│   ├── ARCHITECTURE.md               structure, layers, maps, runtime topology
│   ├── ebpf-firewall-design.md       original design notes
│   ├── QUICKSTART.md                 5-minute setup + testing guide
│   └── FILES_INDEX.md                this file
├── phase1/                           Data path — kernel-space packet filtering
│   ├── phase1_packet_filter.c        XDP program: drop/allow decision per packet
│   ├── phase1_loader.go              loads + pins maps + attaches XDP to an interface
│   ├── go.mod / go.sum               module deps (github.com/cilium/ebpf)
│   └── (build artifacts: phase1_packet_filter.o, phase1-loader)
├── phase2/                           Observability — XDP observer on a separate interface, read-only
│   ├── phase2_ringbuf_events.c       XDP program: streams packet events to a ring buffer
│   ├── phase2_collector.go           reads ring buffer, prints live events + flow stats
│   ├── go.mod / go.sum
│   └── (build artifacts: phase2_ringbuf_events.o, phase2-collector)
├── phase3/                           Policy engine — file-driven rule management
│   ├── phase3_rules_manager.go       loads/validates JSON rules, hot-reloads into the map
│   ├── example_rules.json            13 sample rules (SSH/HTTP/HTTPS allow, ICMP/Telnet/RDP/etc drop)
│   ├── go.mod / go.sum
│   └── (build artifact: phase3-rules-manager)
└── phase4/                           Control plane — REST API
    ├── phase4_api_server.go          HTTP server: health, stats, rules CRUD
    ├── go.mod / go.sum
    └── (build artifact: phase4-api-server)
```

## Endpoints (Phase 4)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | liveness + whether the eBPF maps are attached (no auth) |
| GET | `/api/v1/stats` | packet counters (total/dropped/allowed/icmp_dropped) + rule count |
| GET | `/api/v1/rules` | list all rules |
| POST | `/api/v1/rules` | create a rule (JSON body: id, protocol, dst_port, action, description) |
| PUT | `/api/v1/rules/{id}` | replace a rule |
| DELETE | `/api/v1/rules/{id}` | remove a rule |

`/api/v1/*` requires `Authorization: Bearer <token>` or `X-API-Token`. Defaults: listen `127.0.0.1:8080`, rules file mode `0600`. Optional HTTPS: `-tls-cert` / `-tls-key`.

## Make targets

| Target | Effect |
|---|---|
| `make all` | userspace binaries + BPF objects (BPF skipped on Windows) |
| `make userspace` | four Go binaries (linux/amd64 from Windows) |
| `make bpf` | clang XDP `.o` files (Linux only) |
| `make phase1` / `phase2` / `phase3` / `phase4` | build one phase |
| `make install-deps` | apt-get the toolchain (clang, llvm, libbpf-dev, golang-go, ...) |
| `make verify` | check clang/go are present and kernel version is ≥5.8 |
| `make test` | `go vet` + build check, no artifacts kept |
| `make generate-rules` | copy `example_rules.json` to `rules.json` if it doesn't exist |
| `make clean` | remove all build artifacts |
