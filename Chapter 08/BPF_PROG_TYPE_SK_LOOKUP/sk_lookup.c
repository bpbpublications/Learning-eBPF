#include "sk_lookup.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct sk_lookup_bpf *skel;
  struct bpf_link *link;
  int err;
  struct bpf_program *prog;

  if (argc < 4) {
    fprintf(stderr, "Usage: %s <Server PID> <Server FD> <Listening Ports>\n",
            argv[0]);
    return 1;
  }

  int server_pid = atoi(argv[1]);
  int server_fd = atoi(argv[2]);
  char *listening_ports = argv[3];
  printf("Listening ports: %s\n", listening_ports);

  /* Open load and verify BPF application */
  skel = sk_lookup_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  prog = skel->progs.echo_dispatch;
  if (!prog) {
    fprintf(stderr, "Failed to load BPF program\n");
    return 1;
  }

  int pidfd = -1;
  int dup_server_fd = -1;

  pidfd = syscall(__NR_pidfd_open, server_pid, 0);
  if (pidfd == -1) {
    fprintf(stderr, "Failed to open pidfd: %s\n", strerror(errno));
    goto cleanup;
  }

  // Use pidfd_getfd to duplicate the server's FD
  dup_server_fd = syscall(__NR_pidfd_getfd, pidfd, server_fd, 0);
  if (dup_server_fd == -1) {
    fprintf(stderr, "Failed to duplicate server FD: %s\n", strerror(errno));
    close(pidfd);
    goto cleanup;
  }

  // Insert the duplicated server_fd into socket_map
  uint32_t key = 0;
  uint64_t value = dup_server_fd;
  printf("New server FD: %li\n", value);
  err = bpf_map_update_elem(bpf_map__fd(skel->maps.socket_map), &key, &value,
                            BPF_ANY);
  if (err) {
    fprintf(stderr, "Failed to update socket_map: %s\n", strerror(errno));
    close(dup_server_fd);
    goto cleanup;
  } else {
    printf("Inserted FD: %i into the socket_map\n", value);
  }

  // Insert listening ports into port_map
  char *port_str = strtok(listening_ports, ",");
  while (port_str != NULL) {
    int port = atoi(port_str);
    printf("New listening port: %d\n", port);
    __u8 value = 0; // Mark the port as open
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.port_map), &port, &value,
                              BPF_ANY);
    if (err) {
      fprintf(stderr, "Failed to update port_map for port %d: %s\n", port,
              strerror(errno));
      close(dup_server_fd); // Close dup_server_fd on error
      goto cleanup_dup_fd;
    } else {
      printf("Added port %d to port_map.\n", port);
    }
    port_str = strtok(NULL, ",");
  }

  int netns_fd = open("/proc/self/ns/net", O_RDONLY);
  if (netns_fd < 0) {
    fprintf(stderr, "Failed to open netns: %s\n", strerror(errno));
    goto cleanup;
  } else {
    printf("Opened netns FD at %i\n", netns_fd);
  }

  int prog_fd;
  prog_fd = bpf_program__fd(prog);
  printf("BPF Program FD: %i\n", prog_fd);

  link = bpf_program__attach_netns(prog, netns_fd);
  if (!link) {
    fprintf(stderr, "Failed to attach program to netns: %s\n", strerror(errno));
    close(netns_fd);
    goto cleanup;
  }

  for (;;) {
    sleep(1);
  }

cleanup_dup_fd:
  if (dup_server_fd != -1) {
    close(dup_server_fd);
  }

cleanup:
  sk_lookup_bpf__destroy(skel);
  return -err;
}