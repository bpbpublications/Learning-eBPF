#include "example2.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo) { stop = 1; }

void print_open_count(struct bpf_map *open_count_map) {
  if (!open_count_map) {
    fprintf(stderr, "Error: open_count_map is NULL\n");
    return;
  }

  fprintf(stdout, "Process count:\n");

  int key, next_key, value;

  key = 0;
  while (bpf_map__get_next_key(open_count_map, &key, &next_key,
                               sizeof(next_key)) == 0) {
    if (bpf_map__lookup_elem(open_count_map, &next_key, sizeof(next_key),
                             &value, sizeof(__u64), 0) == 0) {
      printf("PID: %u, `openat` syscall count: %u\n", next_key, value);
    } else {
      fprintf(stderr, "Failed to lookup element for key: %u\n", next_key);
    }
    key = next_key;
  }
}

int main(int argc, char **argv) {
  struct example2_bpf *skel;
  int err;
  struct bpf_map *open_count_map; // Declare open_count_map

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Open, load, and verify BPF application */
  skel = example2_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Attach tracepoint handler */
  err = example2_bpf__attach(skel); // Use the skeleton's attach function
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %s\n",
            strerror(-err)); // More informative error message
    goto cleanup;
  }

  open_count_map =
      bpf_object__find_map_by_name(skel->obj, "openat_count"); // Use skel->obj
  if (!open_count_map) {
    fprintf(stderr, "Failed to find open_count map\n");
    goto cleanup;
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

  while (!stop) {
    fprintf(stderr, ".");
    sleep(1);
  }
  // Print open count
  print_open_count(open_count_map);

cleanup:
  example2_bpf__detach(skel); // Detach before closing
  example2_bpf__destroy(
      skel); // Use destroy instead of individual frees and closes.
  return err;
}