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
int bpf_prog_verdict(struct __sk_buff *skb)
{
    int local_port = skb->local_port;
    int remote_port = bpf_ntohs(skb->remote_port >> 16);

    bpf_trace_printk("bpf_prog_verdict: %d -> %d\n", sizeof("bpf_prog_verdict: %d -> %d\n"), local_port, remote_port);

    // Client to server redirection for local port 10000
    if (local_port == 10000) {
        bpf_trace_printk("bpf_prog_verdict: client -> server\n", sizeof("bpf_prog_verdict: client -> server\n"));
        return bpf_sk_redirect_map(skb, &sock_redir, 0, 0);
    }

    // Server to client redirection for remote port 5201
    if (remote_port == 5201) {
        bpf_trace_printk("bpf_prog_verdict: server -> client\n", sizeof("bpf_prog_verdict: server -> client\n"));
        return bpf_sk_redirect_map(skb, &sock_store, 0, 0);
    }

    // Optional drop logic
    if (local_port == 9999) {
        return SK_DROP;
    }

    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
