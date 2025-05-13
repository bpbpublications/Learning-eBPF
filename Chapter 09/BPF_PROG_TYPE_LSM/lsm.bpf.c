// #include <linux/bpf.h>
// #include <linux/lsm_hooks.h>
// #include <linux/dentry.h>
// #include <linux/path.h>
// #include <linux/string.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include "vmlinux.h"

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

SEC("lsm/file_open")
int BPF_PROG(restrict_tmp_file_open, struct file *file) {
  char path[256];
  struct dentry *dentry = file->f_path.dentry;
  struct vfsmount *mnt = file->f_path.mnt;

  /* Get the full file path */
  if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0)
    return 1; /* Fail closed if path retrieval fails */

  /* Check if the file is in /tmp */
  if (__builtin_memcmp(path, "/tmp", 4) == 0) {
    bpf_printk("LSM: Blocking file open in /tmp: %s\n", path);
    return -EPERM;
  }

  return 0;
}


char _license[] SEC("license") = "GPL";
