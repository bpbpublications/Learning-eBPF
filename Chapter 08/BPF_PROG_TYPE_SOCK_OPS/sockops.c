#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct bpf_object *obj;
  int prog_fd;
  int cgroup_fd;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <cgroup_path>\n", argv[0]);
    return 1;
  }

  const char *cgroup_path = argv[1];

  // Open cgroup directory
  cgroup_fd = open(cgroup_path, O_RDONLY);
  if (cgroup_fd < 0) {
    perror("Failed to open cgroup");
    return 1;
  }

  // Load the compiled BPF program
  obj = bpf_object__open_file("sockops.bpf.o", NULL);
  if (!obj) {
    fprintf(stderr, "Failed to open BPF object file\n");
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Failed to load BPF object\n");
    return 1;
  }

  // Retrieve the program file descriptors
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "modify_buffers");
  // struct bpf_program *prog_egress = bpf_object__find_program_by_name(obj,
  // "egress_filter");

  // if (!prog_ingress || !prog_egress) {
  //     fprintf(stderr, "Failed to find BPF programs in object\n");
  //     return 1;
  // }

  prog_fd = bpf_program__fd(prog);

  // Print the cgroup file descriptor
  printf("Prog FD: %i\n", prog_fd);
  printf("Cgroup FD: %i\n", cgroup_fd);

  // Attach the ingress program
  if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0)) {
    perror("Failed to attach BPF program");
    return 1;
  }

  printf("BPF programs successfully attached to cgroup!\n");

  close(cgroup_fd);
  return 0;
}
