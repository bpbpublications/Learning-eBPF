#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>

// Define sockmap
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

// Define sockhash
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} sock_hash SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
    __u32 rport = bpf_ntohl(msg->remote_port);

    bpf_printk("Message received on port: %u\n", rport);

    if (rport == 80) {
        bpf_printk("Dropping HTTP traffic on port 80\n");
        return SK_DROP;
    }

    if (rport != 1337) {
        bpf_printk("Allowing port %u (not 1337)\n", rport);
        return SK_PASS;
    }

    bpf_printk("Redirecting traffic on port 1337\n");

    // Use this for sockhash
    return bpf_msg_redirect_hash(msg, &sock_hash, &rport, BPF_F_INGRESS);
}

// sockops program for inserting sockets into the map
SEC("sockops")
int sockops_prog(struct bpf_sock_ops *ctx)
{
    __u32 lport = bpf_ntohl(ctx->remote_port);

    if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {

        bpf_printk("Socket established, mapping lport:%u to socket\n", lport);

        // Use this for sockmap:
        bpf_sock_map_update(ctx, &sock_map, &lport, BPF_ANY);

        // Or use this for sockhash:
        bpf_sock_hash_update(ctx, &sock_hash, &lport, BPF_ANY);
    }

    return SK_PASS;
}
