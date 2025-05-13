#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct bpf_object *obj;
  int prog_fd, cgroup_fd;

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

  // Load the BPF object file
  obj = bpf_object__open_file("cgroup_sock.bpf.o", NULL);
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
      bpf_object__find_program_by_name(obj, "block_v4_icmp");
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
  if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE, 0)) {
    perror("Failed to attach BPF program");
    return 1;
  }

  printf("BPF program successfully attached to %s\n", cgroup_path);

  close(cgroup_fd);
  return 0;
}
