// phase2_ringbuf_events.c
// Attaches to the same XDP hook path (as a tc/XDP-adjacent observer) and
// streams per-packet metadata to userspace via a BPF ring buffer.
// Designed to run alongside phase1 for pure observability — it never
// drops packets itself.
//
// Build: clang -O2 -g -target bpf -c phase2_ringbuf_events.c -o phase2_ringbuf_events.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  verdict; /* mirrors phase1's decision when both are loaded; 0xFF = unknown */
    __u16 pkt_len;
};

/* 256KB ring buffer — not pinned; the collector in this process opens it. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* Simple flow tracker: keyed by (src_ip,dst_ip,src_port,dst_port,protocol) hash-ish key. */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, __u64); /* packet count for this flow */
} flows SEC(".maps");

SEC("xdp")
int xdp_event_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    struct flow_key fkey = {
        .src_ip = ip->saddr, .dst_ip = ip->daddr,
        .src_port = src_port, .dst_port = dst_port,
        .protocol = ip->protocol,
    };
    __u64 *count = bpf_map_lookup_elem(&flows, &fkey);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&flows, &fkey, &initial, BPF_ANY);
    }

    struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS; /* ring buffer full — drop the event, not the packet */

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->protocol = ip->protocol;
    evt->verdict = 0xFF; /* phase2 is observe-only; verdict unknown here */
    evt->pkt_len = bpf_ntohs(ip->tot_len);

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
