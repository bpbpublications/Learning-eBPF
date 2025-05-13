#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARCH_NR AUDIT_ARCH_X86_64

int main() {
  int ret;
  char *file_path = "/etc/passwd";
  struct stat stats;

  struct sock_filter filter[] = {
      /* Load architecture */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, 1),

      /* Load system call number */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),

      /* Deny open syscall */
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      /* Allow everything else */
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };

  /* Load the filter */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return 1;
  }

  ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  if (ret < 0) {
    perror("prctl");
    exit(EXIT_FAILURE);
  }
  printf("Filter loaded\n");

  /* Try to stat the file */
  printf("Attempting to stat the file\n");
  ret = stat(file_path, &stats);
  if (ret < 0) {
    perror("stat");
    exit(EXIT_FAILURE);
  } else {
    printf("stat succeeded as expected\n");
  }

  /* Try to open the file */
  int fd = open(file_path, O_RDONLY);
  // Program should error-out here
  if (fd > 0) {
    printf("open succeeded, should not have happened\n");
    close(fd);
  }
  return 0;
}
