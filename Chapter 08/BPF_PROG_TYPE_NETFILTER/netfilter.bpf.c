#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include "bpf_tracing_net.h"

#define NF_DROP 0
#define NF_ACCEPT 1

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
                              void *buffer, uint32_t buffer__sz) __ksym;

SEC("netfilter")
int nf_test(struct bpf_nf_ctx *ctx) {
  struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
  const struct nf_hook_state *state = ctx->state;
  const struct iphdr *iph;
  const struct tcphdr *th;
  u8 buffer_iph[20] = {};
  u8 buffer_th[40] = {};
  struct bpf_dynptr ptr;
  uint8_t ihl;

  if (ctx->skb->len <= 20 || bpf_dynptr_from_skb(skb, 0, &ptr))
    return NF_ACCEPT;

  iph = bpf_dynptr_slice(&ptr, 0, buffer_iph, sizeof(buffer_iph));
  if (!iph)
    return NF_ACCEPT;

  if (state->pf != 2)
    return NF_ACCEPT;

  ihl = iph->ihl << 2;

  th = bpf_dynptr_slice(&ptr, ihl, buffer_th, sizeof(buffer_th));
  if (!th)
    return NF_ACCEPT;

  return th->dest == bpf_htons(80) ? NF_DROP : NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";
