#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u16));
  __uint(value_size, sizeof(__u8));
  __uint(max_entries, 1024);
} port_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 1);
} socket_map SEC(".maps");

SEC("sk_lookup")
int echo_dispatch(struct bpf_sk_lookup *ctx) {
  __u16 port = ctx->local_port;
  bpf_printk("New connection for: %i\n", port);
  __u8 *open = bpf_map_lookup_elem(&port_map, &port);
  if (!open)
    return SK_PASS;

  const __u32 key = 0;
  struct bpf_sock *sk = bpf_map_lookup_elem(&socket_map, &key);
  if (!sk)
    return SK_DROP;

  long err = bpf_sk_assign(ctx, sk, 0);
  bpf_sk_release(sk);
  return err ? SK_DROP : SK_PASS;
}

char _license[] SEC("license") = "GPL";