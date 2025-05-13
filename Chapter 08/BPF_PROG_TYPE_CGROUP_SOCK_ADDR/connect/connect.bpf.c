#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
    struct sockaddr_in sa = {};
    struct svc_addr *orig;

    sa.sin_family = AF_INET;
    sa.sin_port = bpf_htons(33333);
    sa.sin_addr.s_addr = bpf_htonl(0x7f000001);

    if (bpf_bind(ctx, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    return 0;

    /* Rewire traffic destined to port 53 to backend 127.0.0.1:5353. */
    if (ctx->user_port == bpf_htons(53)) {
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(5353);
    }
    return 1;
}
