#include <stddef.h>
#include <inttypes.h>
#include <errno.h>
#include <linux/seg6_local.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip6_addr_t {
  unsigned long long hi;
  unsigned long long lo;
};

struct ip6_srh_t {
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned char type;
  unsigned char segments_left;
  unsigned char first_segment;
  unsigned char flags;
  unsigned short tag;

  struct ip6_addr_t segments[0];
};

SEC("lwt_seg6local")
int encap_srh(struct __sk_buff *skb) {
  uint64_t hi = 0xfd00000000000000;
  struct ip6_addr_t *seg;
  struct ip6_srh_t *srh;
  char srh_buf[72]; // room for 4 segments
  int err;

  srh = (struct ip6_srh_t *)srh_buf;
  srh->nexthdr = 0;
  srh->hdrlen = 8;
  srh->type = 4;
  srh->segments_left = 3;
  srh->first_segment = 3;
  srh->flags = 0;
  srh->tag = 0;

  seg = (struct ip6_addr_t *)((char *)srh + sizeof(*srh));

#pragma clang loop unroll(full)
  for (uint64_t lo = 0; lo < 4; lo++) {
    seg->lo = bpf_cpu_to_be64(4 - lo);
    seg->hi = bpf_cpu_to_be64(hi);
    seg = (struct ip6_addr_t *)((char *)seg + sizeof(*seg));
  }

  err = bpf_lwt_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
  if (err) {
    return BPF_DROP;
  }
  return BPF_REDIRECT;
}

char LICENSE[] SEC("license") = "GPL";