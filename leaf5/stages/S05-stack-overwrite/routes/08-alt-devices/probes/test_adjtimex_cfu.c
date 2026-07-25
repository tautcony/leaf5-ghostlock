/**
 * test_adjtimex_cfu.c — __arm64_sys_adjtimex stack CFU vs task@-0x168
 *
 * Static: frame 0x120, CFU 208B @ SP+8 → abs [0x118, 0x1e8)
 * task @ 0x168 = buffer + 0x50
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <unistd.h>

int main(void) {
  struct timex tx;
  memset(&tx, 0, sizeof(tx));
  tx.modes = 0; /* read / query — should still CFU full struct */

  errno = 0;
  long r = syscall(SYS_adjtimex, &tx);
  printf("adjtimex valid: ret=%ld errno=%d (%s)\n", r, errno,
         r < 0 ? strerror(errno) : "OK");

  errno = 0;
  r = syscall(SYS_adjtimex, (void *)(uintptr_t)0x8);
  printf("adjtimex bad ptr: ret=%ld errno=%d (%s)%s\n", r, errno,
         r < 0 ? strerror(errno) : "OK",
         errno == EFAULT ? "  ← CFU" : "");

  /* clock_adjtime is sibling on some kernels */
#ifdef SYS_clock_adjtime
  errno = 0;
  r = syscall(SYS_clock_adjtime, 0, (void *)(uintptr_t)0x8);
  printf("clock_adjtime bad: ret=%ld errno=%d (%s)%s\n", r, errno,
         r < 0 ? strerror(errno) : "OK",
         errno == EFAULT ? "  ← CFU" : "");
#endif

  printf("sizeof(timex)=%zu (expect ~208 for CFU size)\n", sizeof(tx));
  printf("task slot offset in buffer: 0x50\n");
  return 0;
}
