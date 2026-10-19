# eBPF Firewall

A 4-phase, modular eBPF/XDP firewall: kernel-space packet filtering,
real-time event monitoring, a JSON-driven policy engine, and a REST API —
each phase independently buildable and runnable.

| Doc | Use |
|-----|-----|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Structure, layers, maps, runtime topology |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Build and run |
| [docs/FILES_INDEX.md](docs/FILES_INDEX.md) | Files, HTTP endpoints, Make targets |
| [docs/ebpf-firewall-design.md](docs/ebpf-firewall-design.md) | Original design notes |

> Linux allows one XDP program per interface. Run Phase 1 and Phase 2 on
> different NICs, or stop one before starting the other.

```bash
make verify          # Go present; on Linux also clang + kernel ≥ 5.8
make userspace       # four Go binaries (linux/amd64 when built from Windows)
make bpf             # XDP .o files — Linux + clang only
make all             # userspace + bpf
```

On Linux after a full build: `scripts/run-topology.sh` (filter `eth0`, optional monitor `eth1`).

Requires Linux kernel 5.8+. Go sources build in this workspace; C eBPF
objects need a Linux host with `clang`/`llvm` as the Makefile expects.

## Phases

1. **Filter** — XDP allow/drop from a pinned rules map (`phase1`).
2. **Monitor** — observe-only XDP + ring buffer (`phase2`).
3. **Policy** — JSON rules into `/sys/fs/bpf/firewall_rules` (`phase3`).
4. **API** — REST CRUD and stats (`phase4`).
