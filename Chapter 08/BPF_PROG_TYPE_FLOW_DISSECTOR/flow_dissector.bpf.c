#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BPF_FLOW_DISSECTOR_CONTINUE 129

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct bpf_flow_keys);
} tcp_443_flows SEC(".maps");

static __always_inline int export_flow_keys(struct bpf_flow_keys *keys, int ret) {
    __u32 key = ((__u32) bpf_ntohs(keys->sport) << 16) | bpf_ntohs(keys->dport);
    struct bpf_flow_keys val;

    __builtin_memcpy(&val, keys, sizeof(val));
    bpf_map_update_elem(&tcp_443_flows, &key, &val, BPF_ANY);
    return ret;
}

static __always_inline void *bpf_flow_dissect_get_header(struct __sk_buff *skb,
    __u16 hdr_size,
    void *buffer)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u16 thoff = skb->flow_keys->thoff;
    __u8 *hdr;

    /* Verifies this variable offset does not overflow */
    if (thoff > (USHRT_MAX - hdr_size))
    return NULL;

    hdr = data + thoff;
    if (hdr + hdr_size <= data_end)
    return hdr;

    if (bpf_skb_load_bytes(skb, thoff, buffer, hdr_size))
    return NULL;

    return buffer;
}


SEC("flow_dissector")
int flow_dissect(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    if (keys->n_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph, _iph;
        struct tcphdr *tcp, _tcph;
        struct udphdr *udp, _udph;

		iph = bpf_flow_dissect_get_header(skb, sizeof(*iph), &_iph);
        if (!iph) {
            return BPF_FLOW_DISSECTOR_CONTINUE;
        }
        if (iph->protocol == 89) {
            bpf_printk("Custom OSPF dissector logic\n");
        }
        if (iph->protocol == IPPROTO_ICMP) {
            bpf_printk("ICMP Packet Detected\n");
            return BPF_FLOW_DISSECTOR_CONTINUE;
        }
        if (iph->protocol == IPPROTO_TCP) {
            tcp = bpf_flow_dissect_get_header(skb, sizeof(*tcp), &_tcph);
            if (tcp) {
                if(tcp->dest == 443) {
                    bpf_printk("TCP/443 Packet Detected");
                    return BPF_FLOW_DISSECTOR_CONTINUE;
                }
            }
        }
        else if (iph->protocol == IPPROTO_UDP) {
            udp = bpf_flow_dissect_get_header(skb, sizeof(*udp), &_udph);
            if (udp) {
                bpf_printk("Dissected traffic dest for port %i\n", udp->dest);
                bpf_printk("Dissected traffic from src port %i\n", udp->source);
                if(udp->dest == 443) {
                    bpf_printk("UDP/443 Packet Detected");
                    return BPF_FLOW_DISSECTOR_CONTINUE;
                }
            }
        }
    } else {
        bpf_printk("ETH_P_IP check failed, n_proto: %s\n", keys->n_proto);
    }

    return BPF_FLOW_DISSECTOR_CONTINUE;
}


char _license[] SEC("license") = "GPL";
// #include <stddef.h>
// #include <stdbool.h>
// #include <string.h>
// #include <linux/bpf.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <linux/udp.h>
// #include <linux/if_packet.h>

// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>

// #define BPF_FLOW_DISSECTOR_CONTINUE 129

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u32);
//     __type(value, struct bpf_flow_keys);
// } tcp_443_flows SEC(".maps");

// static __always_inline int export_flow_keys(struct bpf_flow_keys *keys, int ret) {
//     __u32 key = ((__u32) bpf_ntohs(keys->sport) << 16) | bpf_ntohs(keys->dport);
//     struct bpf_flow_keys val;

//     __builtin_memcpy(&val, keys, sizeof(val));
//     bpf_map_update_elem(&tcp_443_flows, &key, &val, BPF_ANY);
//     return ret;
// }

// SEC("flow_dissector")
// int flow_dissect(struct __sk_buff *skb) {
//     struct bpf_flow_keys *keys = skb->flow_keys;
//     if (!keys)
//         return BPF_FLOW_DISSECTOR_CONTINUE;  // Ensure keys are valid

//     if (keys->n_proto == bpf_htons(ETH_P_IP)) {
//         struct iphdr *iph, _iph;
//         struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
//         bpf_printk("IP-proto: %d", keys->ip_proto);
//         if (keys->ip_proto != IPPROTO_TCP) {
//             bpf_printk("FLOW DISSECTOR CONTINUE1, non-TCP");
//             return BPF_FLOW_DISSECTOR_CONTINUE;
//         }

//         if (keys->dport != bpf_htons(443)) {
//             bpf_printk("FLOW DISSECTOR CONTINUE2, non-443");
//             return BPF_FLOW_DISSECTOR_CONTINUE;
//         }

//         bpf_printk("TCP/443 detected");
//         export_flow_keys(keys, BPF_OK);
//     }

//     bpf_printk("FLOW DISSECTOR CONTINUE3");
//     return BPF_FLOW_DISSECTOR_CONTINUE;
// }

// char _license[] SEC("license") = "GPL";
