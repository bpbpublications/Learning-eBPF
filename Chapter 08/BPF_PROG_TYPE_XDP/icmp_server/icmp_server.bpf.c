#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>




// #define ICMP_ECHO 8 // Definition of ICMP_ECHO
// #define ICMP_ECHOREPLY 0     // Definition of ICMP_ECHOREPLY
// #define ICMP_ECHO_LEN 64

// static __always_inline void swap_src_dst_mac(struct ethhdr *eth) // Added function
// {
//     __u8 tmp[ETH_ALEN];

//     memcpy(tmp, eth->h_source, ETH_ALEN);
//     memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
//     memcpy(eth->h_dest, tmp, ETH_ALEN);
// }

// static __always_inline int icmp_check(struct xdp_md *ctx, int type) {
//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;
//     struct ethhdr *eth = data;
//     struct icmphdr *icmph;
//     struct iphdr *iph;

//     if (data + sizeof(*eth) + sizeof(*iph) + ICMP_ECHO_LEN > data_end)
//         return XDP_ABORTED; // Changed to XDP_ABORTED

//     if (eth->h_proto!= bpf_htons(ETH_P_IP))
//         return XDP_PASS;

//     iph = data + sizeof(*eth);

//     if (iph->protocol!= IPPROTO_ICMP)
//         return XDP_PASS;

//     if (bpf_ntohs(iph->tot_len) - sizeof(*iph)!= ICMP_ECHO_LEN)
//         return XDP_PASS;

//     icmph = data + sizeof(*eth) + sizeof(*iph); // Removed extra 's'
//     if (icmph->type!= type)
//         return XDP_PASS;

//     return XDP_TX;
// }

// SEC("xdp")
// int xdping_server(struct xdp_md *ctx)
// {
//     void *data = (void *)(long)ctx->data;
//     struct ethhdr *eth = data;
//     struct icmphdr *icmph;
//     struct iphdr *iph;
//     __be32 raddr;
//     int ret;

//     ret = icmp_check(ctx, ICMP_ECHO);

//     if (ret!= XDP_TX)
//         return ret;

//     iph = data + sizeof(*eth);
//     icmph = data + sizeof(*eth) + sizeof(*iph);
//     raddr = iph->saddr;

//     swap_src_dst_mac(eth); // Pass the Ethernet header to the function
//     iph->saddr = iph->daddr;
//     iph->daddr = raddr;
//     icmph->type = ICMP_ECHOREPLY;
//     icmph->checksum = 0;
//     icmph->checksum += __constant_htons(0x0800);  // Adjust checksum for type changef

//     bpf_trace_printk("Sent ICMP Echo Reply to %x\\n", iph->daddr);
//     return XDP_TX;
// }


SEC("xdp/main")
int xdping_server(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only process IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Only process ICMP packets
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_DROP;

    // Only respond to ICMP Echo Requests
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    // Swap MAC addresses
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap IP addresses
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Modify ICMP packet to Echo Reply
    icmp->type = ICMP_ECHOREPLY;
    icmp->checksum += __constant_htons(0x0800);  // Adjust checksum for type change

    bpf_printk("ICMP Reply\n");
    return XDP_TX; // Transmit back to sender
}

char _license[] SEC("license") = "GPL";
