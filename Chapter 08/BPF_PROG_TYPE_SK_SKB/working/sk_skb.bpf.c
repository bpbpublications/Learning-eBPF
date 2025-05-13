#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 10);
    __type(key, int);
    __type(value, int);
} sock_store SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 10);
    __type(key, int);
    __type(value, int);
} sock_redir SEC(".maps");

SEC("sk_skb")
int bpf_prog_verdict(struct __sk_buff *skb) {
    int key = 0;
    char enter[] = "bpf_prog_verdict: enter\n";
    bpf_trace_printk(enter, sizeof(enter));

    // check if is ip type
    if (bpf_ntohs(skb->protocol) != 0x800) {
        char fmt[] = "bpf_prog_verdict: not ip type\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return SK_PASS;
    }
    char fmt[] = "bpf_prog_verdict: %d -> %d \n";
    bpf_trace_printk(fmt, sizeof(fmt), skb->local_port, bpf_ntohs(skb->remote_port >> 16));

    if (skb->local_port == 5201 || skb->local_port == 10000) {
        char fmt[] = "bpf_prog_verdict: client -> server\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return bpf_sk_redirect_map(skb, &sock_redir, 0, 0);
    } else if (bpf_ntohs(skb->remote_port >> 16) == 5201) {
        char fmt[] = "bpf_prog_verdict: server -> client\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return bpf_sk_redirect_map(skb, &sock_store, 0, 0);
    }

    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";

