// phase1_packet_filter.c
// XDP (eXpress Data Path) packet filter — runs in kernel space.
// Drops/allows packets based on a rule map populated by phase3 (rules manager).
//
// Build: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c phase1_packet_filter.c -o phase1_packet_filter.o
// Requires: libbpf-dev, linux kernel headers (5.8+)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_ALLOW 0
#define ACTION_DROP  1

/* ---- Rule key/value shared with phase3 (rules manager) ----
 * NOT packed: natural alignment puts a 1-byte pad after `protocol` so
 * `dst_port` lands on a 2-byte boundary at offset 2 (struct size 4).
 * This must exactly match the Go-side ruleKey struct in phase3/phase4 —
 * see the layout comment there. */
struct rule_key {
    __u8  protocol;   /* IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1, 0 = wildcard */
    __u16 dst_port;   /* 0 = wildcard (ignored for ICMP) */
};

struct rule_value {
    __u8  action;      /* ACTION_ALLOW / ACTION_DROP */
    __u64 match_count; /* incremented on every hit, for stats/debugging */
};

/* Pinned at /sys/fs/bpf/firewall_rules so phase3 can update it live. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} firewall_rules SEC(".maps");

/* Global stats — index 0=total, 1=dropped, 2=allowed, 3=icmp_dropped */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} firewall_stats SEC(".maps");

enum { STAT_TOTAL = 0, STAT_DROPPED = 1, STAT_ALLOWED = 2, STAT_ICMP_DROPPED = 3 };

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&firewall_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* Default policy when no rule matches: allow everything except ICMP. */
static __always_inline int default_policy(__u8 protocol)
{
    if (protocol == IPPROTO_ICMP) {
        bump_stat(STAT_ICMP_DROPPED);
        return ACTION_DROP;
    }
    return ACTION_ALLOW;
}

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    bump_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; /* malformed, let the kernel stack decide */

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump_stat(STAT_ALLOWED);
        return XDP_PASS; /* only IPv4 is filtered in phase 1 */
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 dst_port = 0;
    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(udp->dest);
    }

    /* Rule lookup order: exact (proto+port) -> proto wildcard -> default policy */
    struct rule_key key = { .protocol = protocol, .dst_port = dst_port };
    struct rule_value *rule = bpf_map_lookup_elem(&firewall_rules, &key);

    if (!rule) {
        key.dst_port = 0; /* protocol-level wildcard rule */
        rule = bpf_map_lookup_elem(&firewall_rules, &key);
    }

    __u8 action;
    if (rule) {
        __sync_fetch_and_add(&rule->match_count, 1);
        action = rule->action;
    } else {
        action = default_policy(protocol);
    }

    if (action == ACTION_DROP) {
        bump_stat(STAT_DROPPED);
        return XDP_DROP;
    }

    bump_stat(STAT_ALLOWED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
