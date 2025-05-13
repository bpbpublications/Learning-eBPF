#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define SERV4_IP 0xC0A80135 /* 192.168.1.53 */
#define SERV4_PORT 5000

SEC("cgroup/recvmsg4")
int recvmsg4_prog(struct bpf_sock_addr *ctx)
{
struct bpf_sock *sk;

sk = ctx->sk;

if (sk->family != AF_INET)
return 1;

if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
return 1;

ctx->user_ip4 = bpf_htonl(SERV4_IP);
ctx->user_port = bpf_htons(SERV4_PORT);

return 1;
}
