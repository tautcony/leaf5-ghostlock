#include <fcntl.h>
#include <stdio.h>
int main() {
  printf("F_SETPIPE_SZ=%d (0x%x)\n", F_SETPIPE_SZ, F_SETPIPE_SZ);
  printf("F_GETPIPE_SZ=%d (0x%x)\n", F_GETPIPE_SZ, F_GETPIPE_SZ);
  return 0;
}
