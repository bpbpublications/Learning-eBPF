#include <linux/bpf.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf_sockopt_helpers.h>

SEC("cgroup/getsockname4")
int getsockname4(struct bpf_sock_addr *ctx)
{
    if (!get_set_sk_priority(ctx))
        return 1;

    if (ctx->user_port == bpf_htons(6000)) {
        ctx->user_ip4 = bpf_htonl(0x01020304);
        ctx->user_port = bpf_htons(60001);
    }
    return 1;
}
