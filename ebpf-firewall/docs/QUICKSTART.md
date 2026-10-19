# Quickstart

Tested build environment: Ubuntu 24.04, Go 1.22+, clang/LLVM 18, kernel 6.x.
Should work on any kernel 5.8+.

## 1. Install dependencies (~2 min)

```bash
make install-deps
```

This installs `clang`, `llvm`, `libelf-dev`, `libpcap-dev`, `libbpf-dev`,
`linux-libc-dev`, and `golang-go` via apt. Go module dependencies
(`cilium/ebpf`) resolve automatically the first time you `go build` —
no manual `go get` needed, each phase directory already has its own
`go.mod`/`go.sum`.

Verify your environment is ready:

```bash
make verify
```

## 2. Build everything

```bash
make all          # userspace + BPF (BPF on Linux only)
make userspace    # four Go binaries
make bpf          # clang XDP objects — needs Linux
```

Or build one phase at a time:

```bash
make phase1   # XDP packet filter (.o + loader binary)
make phase2   # ring buffer event monitor (.o + collector binary)
make phase3   # rules manager binary
make phase4   # REST API binary
```

`make test` runs `go vet` + a build check on all four Go binaries without
producing artifacts — useful in CI.

## 3. Run everything (needs root for phases 1–3; find your interface first)

```bash
ip link show          # find your interface name, e.g. eth0, ens33, wlan0
```

> Important: Linux allows only one active XDP program per interface. Phase 1
> and Phase 2 cannot both attach to the same NIC at the same time. For a
> realistic setup, run Phase 1 on one interface and Phase 2 on a different
> interface (or stop the XDP filter before starting the monitor).

Open three terminals for the active firewall path, then optionally run the
monitor on a second NIC:

```bash
# Terminal 1 — Packet Filter (blocks ICMP by default, honors rules_map)
sudo ./phase1/phase1-loader -interface eth0

# Terminal 2 — Rules Manager (loads JSON rules into the map, hot-reloads)
sudo ./phase3/phase3-rules-manager -rules phase3/example_rules.json

# Terminal 3 — REST API (no root needed; talks to the pinned maps)
# -seed loads the JSON into API memory only. Phase 3 (above) is what
# writes the full rule set into the kernel map.
./phase4/phase4-api-server -listen :8080 -rules-file phase3/example_rules.json -seed
```

Optional observer on a second interface:

```bash
sudo ./phase2/phase2-collector -interface eth1
```

> Phase 1 must be started **before** Phase 3 or Phase 4, since it's the
> one that creates and pins `/sys/fs/bpf/firewall_rules` and
> `/sys/fs/bpf/firewall_stats`. Phase 3/4 will run in file-only mode
> (rules persist to disk, but nothing gets enforced) until Phase 1 is up.

## 4. Test it

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/stats
curl http://localhost:8080/api/v1/rules

# generate some traffic
ping -c 3 8.8.8.8        # should be dropped (default policy blocks ICMP)

# add a custom rule via the API
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{"id":"block-telnet","protocol":"tcp","dst_port":23,"action":"drop","description":"custom rule"}'

# remove it
curl -X DELETE http://localhost:8080/api/v1/rules/block-telnet
```

Watch Phase 1's terminal — it prints stats every 5s (`total`, `dropped`,
`allowed`, `icmp_dropped`). Watch Phase 2's terminal for a live per-packet
event stream and periodic flow counts.

## 5. Stop everything

`Ctrl+C` each terminal. Phase 1 and Phase 2 detach their XDP programs on
exit. The pinned maps under `/sys/fs/bpf/` persist until you remove them
manually:

```bash
sudo rm /sys/fs/bpf/firewall_rules /sys/fs/bpf/firewall_stats
```

(If you restart Phase 1 without removing these, it will fail to re-pin
them — either delete them first, or modify the loader to reuse existing
pins.)

## Common issues

| Symptom | Fix |
|---|---|
| `removing memlock rlimit` fails | Run with `sudo` |
| `attaching XDP program` fails with "operation not supported" | Your NIC/driver may not support XDP generic mode either — try a different interface, or check `dmesg` |
| Phase 3/4 log "rules map not available" | Start `phase1-loader` first |
| `curl: (7) Failed to connect` on :8080 | Phase 4 isn't running, or a firewall rule (ironically) is blocking the port |
| `make install-deps` partial failures on `security.ubuntu.com` | Harmless if `clang`/`go` still installed — re-run `apt-get install -y --fix-missing <pkg>` for anything missing |
| Rules don't seem to apply | Confirm you passed `-seed` to phase4, or that phase3 is running and watching the file |
