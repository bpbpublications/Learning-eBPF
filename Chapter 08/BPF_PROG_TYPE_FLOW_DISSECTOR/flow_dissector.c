#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PIN_PATH "/sys/fs/bpf/flow_dissector"

int main() {
  struct bpf_object *obj;
  int prog_fd;

  // Load the BPF object file
  obj = bpf_object__open_file("flow_dissector.bpf.o", NULL);
  if (!obj) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  // Load program
  if (bpf_object__load(obj)) {
    fprintf(stderr, "Failed to load BPF object\n");
    return 1;
  }

  // Get first program in object
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "flow_dissect");
  if (!prog) {
    fprintf(stderr, "Failed to find BPF program\n");
    return 1;
  }

  // Get file descriptor for the program
  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "Failed to get BPF program FD\n");
    return 1;
  }

  // Attach program to cgroup
  if (bpf_prog_attach(prog_fd, 0, BPF_FLOW_DISSECTOR, 0)) {
    perror("Failed to attach BPF program");
    return 1;
  }

  if (bpf_program__pin(prog, PIN_PATH)) {
    fprintf(stderr, "Failed to pin BPF program\n");
    goto cleanup;
  }

  printf("Waiting for flow data...\n");

  for (;;) {
    sleep(1);
  }

cleanup:
  bpf_program__unpin(prog, PIN_PATH);
  bpf_prog_detach(prog_fd, BPF_FLOW_DISSECTOR);
}