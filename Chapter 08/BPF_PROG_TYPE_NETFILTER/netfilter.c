#include "netfilter.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct netfilter_bpf *skel;
  struct bpf_program *prog;
  struct bpf_link *link;
  // int ret;

  /* Open load and verify BPF application */
  skel = netfilter_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  prog = skel->progs.nf_test;
  if (!prog) {
    fprintf(stderr, "Failed to load BPF program\n");
    return 1;
  }

  struct bpf_netfilter_opts opts = {.sz = sizeof(struct bpf_netfilter_opts),
                                    .pf = NFPROTO_IPV4,
                                    .hooknum = NF_INET_LOCAL_OUT,
                                    .priority = 1,
                                    .flags = 0};
  link = bpf_program__attach_netfilter(prog, &opts);
  if (!link) {
    fprintf(stderr, "Failed to attach BPF program\n");
    goto cleanup;
  }

  for (;;) {
    sleep(1);
  }

cleanup:
  netfilter_bpf__detach(skel);
  netfilter_bpf__destroy(skel);
}
