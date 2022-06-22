#include <stdio.h>
#include <sys/resource.h>

int main() {
  struct rlimit lim_stack;
  struct rlimit lim_process;
  struct rlimit lim_file;
  getrlimit(RLIMIT_STACK, &lim_stack);
  printf("stack size: %ld\n", lim_stack.rlim_cur);
  getrlimit(RLIMIT_NPROC, &lim_process);
  printf("process limit: %ld\n", lim_process.rlim_cur);
  getrlimit(RLIMIT_NOFILE, &lim_file);
  printf("max file descriptors: %ld\n", lim_file.rlim_cur);
  return 0;
}
