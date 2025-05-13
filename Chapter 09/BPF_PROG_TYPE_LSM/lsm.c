#include "lsm.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct lsm_bpf *skel;
  int err;

  /* Open load and verify BPF application */
  skel = lsm_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Attach tracepoint handler */
  err = lsm_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  for (;;) {
    sleep(1);
  }

cleanup:
  lsm_bpf__destroy(skel);
  return -err;
}
