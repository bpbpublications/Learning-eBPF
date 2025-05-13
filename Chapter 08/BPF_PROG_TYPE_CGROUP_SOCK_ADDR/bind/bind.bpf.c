#include <linux/stddef.h>
#include <linux/bpf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/bind4")
int bind_v4_prog(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk;

    sk = ctx->sk;
    if (!sk)
        return 0;

    if (sk->family != AF_INET)
        return 0;

    if (ctx->type != SOCK_STREAM)
        return 0;

    return 1;
}
