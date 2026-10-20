# Security review — eBPF Firewall

**Scope:** this repository (`phase1`–`phase4`, scripts, sample rules, docs).  
**Date:** 2026-10-19  
**Review type:** static code review of the current tree (no remote exploit testing).

This document lists every material security finding, residual risk, and what was already fixed. It is an audit report, not a penetration-test playbook.

---

## Summary

| Area | Status |
|------|--------|
| Phase 4 API authentication | **Fixed** (token required for `/api/v1/*`) |
| Phase 4 HTTPS / bind policy | **Fixed** (loopback default; TLS or explicit insecure HTTP) |
| Rules file permissions | **Fixed in Phase 4 persist** (`0600`); Phase 3 copy/load still may leave `0644` |
| Packet filter policy | **Fail-open** for unmatched IPv4 TCP/UDP; ICMP dropped by default |
| IPv6 / VLAN / fragments | **Not filtered** (pass) |
| BPF map and process privilege | **Root/CAP_BPF** can change enforcement; maps persist after detach |
| Remaining API gaps | Shared static token, no RBAC, no audit log, health info leak |

**Overall:** the three original API findings are addressed in code. The datapath is still a **lab / host demo firewall**, not a production network-policy engine. Highest remaining risk is **incorrect or incomplete packet decisions** (allow-by-default, IPv6 pass) plus **operator flags** that can turn auth/TLS off.

---

## What was already fixed (original findings)

### Finding A — Unauthenticated API (was high)

**Before:** handlers had no identity check; `http.ListenAndServe` served CRUD to anyone who could reach the port.

**Now (`phase4/phase4_api_server.go`):**

- `/api/v1/stats`, `/api/v1/rules`, `/api/v1/rules/{id}` require `Authorization: Bearer <token>` or `X-API-Token`.
- Compare uses `crypto/subtle.ConstantTimeCompare`.
- Empty token is rejected at startup unless `-allow-insecure-no-auth`.
- `/health` stays unauthenticated (liveness only).
- Tests: `phase4/phase4_api_server_test.go` (`TestAuthRejectsUnauthenticatedAPI`, `TestAuthAllowsBearerAndHeader`).

**Residual:** one shared secret, visible in `ps` if passed as `-api-token`, and in shell history if exported. No rotation, no per-user roles, no lockout.

### Finding B — Plain HTTP (was configuration risk)

**Before:** always `ListenAndServe`, default listen `:8080` (all interfaces).

**Now:**

- Default listen `127.0.0.1:8080`.
- `-tls-cert` + `-tls-key` → `ListenAndServeTLS`.
- Non-loopback plain HTTP refused unless `-allow-insecure-http` (intended for a trusted reverse proxy).
- Server timeouts: ReadHeader 5s, Read/Write 15s, Idle 60s.

**Residual:** Go default TLS config (no custom MinVersion in this file; Go 1.22 defaults are TLS 1.2+). Reverse-proxy mode trusts the operator to actually terminate TLS. Loopback HTTP is still plaintext on that host.

### Finding C — Rules file mode `0644` (was local disclosure)

**Before:** `os.WriteFile(..., 0644)` — other local users could read policy JSON.

**Now:** atomic write + `chmod 0600` in Phase 4; seed load also tightens the existing file.

**Residual:** `phase3/example_rules.json` in git is world-readable by design. `cp` to `phase3/rules.json` (`make generate-rules`) does not chmod. Phase 3 never rewrites the file, so a `0644` copy stays readable until Phase 4 persists.

---

## Remaining threats (all phases)

### 1. Default packet policy is fail-open — High (policy)

**Where:** `phase1/phase1_packet_filter.c` `default_policy()`.

Unmatched IPv4 TCP/UDP is **allowed**. Only unmatched ICMP is dropped. Sample JSON then *adds* more allows (SSH/HTTP/HTTPS/DNS/NTP) and some port drops.

**Why it matters:** a missing or wiped rules map (Phase 3 full rewrite race, Phase 1 started with empty map, Phase 4 file-only mode) means most inbound IPv4 services stay reachable. This is the opposite of a typical production default-deny firewall.

**Mitigation:** change default to drop (or require an explicit allow-all rule); keep a known-good pin; do not run Phase 3 wipe concurrently with Phase 4.

### 2. IPv6, VLAN, and non-IPv4 pass unfiltered — High (bypass of intended filter)

**Where:** Phase 1 XDP: `eth->h_proto != ETH_P_IP` → `XDP_PASS`.

- IPv6 is never inspected.
- 802.1Q / QinQ tagged frames are not unwrapped, so they look non-IPv4 and pass.
- Non-IP (ARP, etc.) passes (usually desired).

**Why it matters:** on a dual-stack or trunked NIC, an operator who believes “the XDP firewall is on” may still be fully open on IPv6 or tagged IPv4.

**Mitigation:** parse VLAN tags; add IPv6 rules or default-drop IPv6 until supported.

### 3. No source address, CIDR, or direction in the key — High (policy)

**Where:** `struct rule_key` is protocol + destination port only (plus a proto-level wildcard on `dst_port == 0`).

Sample rules **allow SSH/HTTP/HTTPS from any source**. There is no “established only”, no interface-specific policy, no Kubernetes identity.

**Why it matters:** “allow port 22” is global for that ingress NIC. Compromised token or a bad JSON file can open a service to the world.

### 4. Destination-port `0` is a protocol wildcard — Medium

**Where:** Phase 1 lookup: exact proto+port, then proto with `dst_port = 0`.

A single rule `{protocol: tcp, dst_port: 0, action: allow}` allows **all TCP**. Authenticated API or Phase 3 JSON can install that.

**Mitigation:** reject `dst_port == 0` except for ICMP, or treat 0 as literal port 0 only.

### 5. Pinned BPF maps = live kernel policy, persist after exit — Medium

**Where:** `/sys/fs/bpf/firewall_rules`, `/sys/fs/bpf/firewall_stats`. Phase 1 `MkdirAll(..., 0755)`. Pins are **not** removed on Ctrl+C.

Anyone with BPF/map access (typically **root**) can change or delete rules independently of the API. A later Phase 1 start can fail if pins already exist (availability), or reuse old policy (stale allow/drop).

Phase 4 as a normal user often cannot open pins (logs “file-only mode”) — then the API **does not enforce** what operators think they just POSTed.

**Mitigation:** document required capabilities; fail the API if maps are required; unlink pins on a documented uninstall path; restrict bpffs permissions.

### 6. Phase 3 vs Phase 4 map race — Medium

Phase 3 **wipes every map key** then rewrites from file. Phase 4 writes incremental CRUD to the same map and file.

Concurrent use can drop rules, re-apply deleted rules, or leave map and JSON out of sync.

### 7. Shared API token and insecure escape hatches — Medium (operator)

Flags `-allow-insecure-no-auth` and `-allow-insecure-http` restore the original exposure if used on a reachable address.

`scripts/run-topology.sh` **prints** a generated `FIREWALL_API_TOKEN` to the terminal.

`-api-token` on the command line is visible to other users via `ps`.

**Mitigation:** prefer env var; do not log the token; disable insecure flags in any shared environment; do not paste tokens into tickets.

### 8. `/health` information disclosure — Low

Unauthenticated JSON includes `rules_map_up` and `stats_map_up`. That helps operators and also tells an attacker whether kernel maps are attached.

### 9. No authorization model beyond “has token” — Medium

Any valid token can list, create, replace, and delete **all** rules. PUT on a missing id **creates** a rule. No audit trail of who changed policy.

### 10. Request handling gaps — Low to Medium

- Body size limited to 1 MiB (good).
- Rule `id` is not length/charset-limited (large or odd IDs in JSON).
- Path `/api/v1/rules/{id}` does not validate `id` (slash in id is a different path; not a file-path traversal into the OS because persist uses a fixed `-rules-file`).
- No rate limit: a short token could be guessed (use a long random token).
- Error strings can include persist/eBPF errors (minor internal detail leak).
- No method restriction on `/health` (any HTTP method returns 200 JSON).

### 11. XDP parser edge cases — Low to Medium (correctness)

Phase 1/2:

- Only Ethernet + IPv4. IP options: `ihl * 4` used to find L4; short/malformed headers `XDP_PASS`.
- Fragments: later fragments without L4 header may not match port rules and then **default-allow**.
- Generic XDP (`XDPGenericMode`) is compatibility-first; native driver mode is optional (`-driver-mode`).

These are parser limitations, not remote code execution in this review.

### 12. Phase 2 packet logging — Medium (privacy / host confidentiality)

Collector prints 5-tuples (src/dst IP and ports) to stdout. On a shared machine or copied logs, that is traffic metadata disclosure. Ring buffer is process-local (not pinned) — good. LRU flow map is 8192 entries in-kernel while the process runs.

Use `-quiet` if you only need counts.

### 13. Privileged loaders — Expected, still a threat class

Phase 1/2 need memlock + XDP attach (root or capabilities). Loading an attacker-controlled `-object` `.o` is arbitrary kernel BPF — same as giving that user root on the datapath. Do not run loaders against untrusted object files.

Phase 3 needs write access to the pinned rules map (typically root).

### 14. Sample policy itself — Medium (deployment)

`phase3/example_rules.json` allows 22, 80, 443, 53, 123 from **any** source and drops a few known-bad ports. Copying this to production is an **open management plane** on SSH/HTTP if the NIC faces a network.

### 15. Supply chain / build — Low (this repo)

- Four separate `go.mod` files pin `github.com/cilium/ebpf v0.15.0`.
- `replace` directives for `golang.org/x/sys` and `golang.org/x/exp`.
- `make install-deps` runs `apt-get` as root.
- No SBOM, no image signing, no Kubernetes RBAC (this is not a k8s controller).

---

## Threat model (what an attacker can try)

Assumptions: Linux host, Phase 1 attached to a NIC, Phase 4 may be running.

| Attacker | Can they change drops/allows? | Notes |
|----------|-------------------------------|--------|
| Unauthenticated remote, API on `127.0.0.1` only | No (if they are off-box) | Local users on the host can still curl localhost if they steal the token or you used `-allow-insecure-no-auth` |
| Unauthenticated remote, API bound `0.0.0.0` without token | **Yes, if insecure flags used** | Startup should refuse this unless flags are set |
| Unauthenticated remote, token required, TLS or loopback | No to API | Datapath still fail-open / IPv6 pass |
| Network peer sending IPv6 or VLAN-tagged IPv4 | Traffic may **bypass** filter | See findings 2 |
| Network peer hitting ports with no drop rule | **Allowed** | See finding 1 |
| Local root | Yes | BPF maps, XDP, files |
| Other local Unix user | Read rules file only if still `0644`; API if token leaked | Phase 4 persist is `0600` |
| Stolen `FIREWALL_API_TOKEN` | Full rule CRUD | Same as admin of the API |

This review did **not** run live packet tests on a NIC. Confirm IPv6/VLAN/default-allow on a lab host if you need evidence for a specific deployment.

---

## What is in good shape

- XDP programs check `data_end` before header reads (basic verifier-safe bounds).
- Phase 2 never `XDP_DROP`s (observe-only).
- Phase 3 validates protocol/action before map writes.
- Phase 4 validates protocol/action; JSON body size cap; auth tests; loopback/TLS policy tests; private file write helper.
- CSRF is not relevant while the secret is a header token, not a cookie.

---

## Recommended next fixes (priority)

1. **Default-deny** in Phase 1 for unmatched IPv4 (and IPv6).
2. Parse **VLAN** tags; decide IPv6 policy explicitly.
3. Reject or document **port 0 wildcards**.
4. Make Phase 4 **fail** if pinned maps are required but missing (no silent file-only “success”).
5. Prefer **env token**; never print it; drop `-allow-insecure-*` outside labs.
6. `chmod 0600` in Phase 3 / `generate-rules`.
7. Audit log (timestamp, action, rule id) for API mutations.
8. One writer for the map (either GitOps Phase 3 **or** API, not both).

---

## File checklist

| Path | Security role |
|------|----------------|
| `phase1/phase1_packet_filter.c` | Enforcement; default-allow; IPv4-only |
| `phase1/phase1_loader.go` | Privileged attach; persistent pins |
| `phase2/phase2_ringbuf_events.c` | Observe-only; metadata in kernel maps |
| `phase2/phase2_collector.go` | Prints 5-tuples |
| `phase3/phase3_rules_manager.go` | Privileged map wipe/reload; no chmod |
| `phase3/example_rules.json` | Broad allow ports |
| `phase4/phase4_api_server.go` | Auth, TLS policy, `0600` persist |
| `phase4/phase4_api_server_test.go` | Auth and listen-policy tests |
| `scripts/run-topology.sh` | sudo + prints API token |

---

## Verification commands (isolated / local)

These only check **your** process on localhost. They are not attacks on other systems.

```bash
export FIREWALL_API_TOKEN="$(openssl rand -hex 32)"
./phase4/phase4-api-server -listen 127.0.0.1:8080 -rules-file phase3/example_rules.json -seed

curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/health
# expect 200

curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/api/v1/rules
# expect 401

curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $FIREWALL_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/rules
# expect 200
```

```bash
cd phase4 && go test ./...
```

On Linux, after a Phase 4 persist:

```bash
stat -c "%a %n" phase3/example_rules.json
# prefer 600 after the API has written the file
```
