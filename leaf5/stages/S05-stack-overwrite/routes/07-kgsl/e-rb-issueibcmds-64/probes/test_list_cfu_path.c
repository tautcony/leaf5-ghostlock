/**
 * test_list_cfu_path.c — Prove which ISSUEIBCMDS path hits CFU of ibdesc.
 *
 * Binary fact (vmlinux kgsl_ioctl_rb_issueibcmds):
 *   flags byte @ cmd+0x18 bit2 == 0 → kgsl_drawobj_cmd_add_ibdesc (NO CFU)
 *   flags byte @ cmd+0x18 bit2 == 1 → kgsl_drawobj_cmd_add_ibdesc_list (CFU)
 *
 * Hypothesis: prior probes used flags=0, so crash-pattern ibdesc was NEVER
 * copied onto the kernel stack. ret=0 ≠ stack CFU of user ibdesc.
 *
 * errno matrix:
 *   bad list ptr + list flag → EFAULT if CFU reached
 *   bad list ptr + flags=0   → not EFAULT (no CFU of list)
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IOC(nr, sz)                                                        \
  (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) |                        \
   (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

/* Native 32B issueibcmds — layout from handler field uses */
struct issueib_native {
  uint32_t drawctxt_id; /* +0x00 */
  uint32_t flags;       /* +0x04 — also try stuffing bit2 here */
  uint64_t ibdesc_addr; /* +0x08 */
  uint32_t numibs;      /* +0x10 */
  uint32_t timestamp;   /* +0x14 */
  uint32_t flags2;      /* +0x18 — handler reads byte here for list bit2 */
  uint32_t pad;         /* +0x1c */
} __attribute__((packed));

/* Compat 20B used by older probes */
struct issueib_compat20 {
  uint32_t drawctxt_id;
  uint32_t flags;
  uint32_t ibdesc_addr;
  uint32_t timestamp;
  uint32_t numibs;
} __attribute__((packed));

static void try_one(int fd, uint32_t ctx, const char *tag, uint32_t cmd,
                    void *arg) {
  errno = 0;
  int r = ioctl(fd, cmd, arg);
  int e = errno;
  printf("  %-28s ret=%d errno=%d (%s)%s\n", tag, r, e,
         r < 0 ? strerror(e) : "OK",
         e == EFAULT ? "  ← CFU-like EFAULT" : "");
}

int main(void) {
  int fd = open("/dev/kgsl-3d0", O_RDWR);
  if (fd < 0) {
    printf("open kgsl: errno=%d\n", errno);
    return 1;
  }

  struct {
    uint32_t f;
    uint32_t id;
  } ctx = {0x12, 0};
  if (ioctl(fd, IOC(0x13, 0x08), &ctx) < 0) {
    printf("CREATE failed errno=%d\n", errno);
    return 1;
  }
  printf("ctx_id=%u\n\n", ctx.id);

  /* Valid ibdesc in userspace (content irrelevant for EFAULT test) */
  struct {
    uint64_t ga;
    uint64_t sw;
  } ib = {0, 1};
  void *bad = (void *)(uintptr_t)0x8; /* unmapped low page */

  printf("=== A: native 0x20, flags@+0x04, list bit via flags2@+0x18 ===\n");
  {
    struct issueib_native n;
    memset(&n, 0, sizeof(n));
    n.drawctxt_id = ctx.id;
    n.ibdesc_addr = (uint64_t)(uintptr_t)bad;
    n.numibs = 1;

    n.flags = 0;
    n.flags2 = 0;
    try_one(fd, ctx.id, "native flags=0 flags2=0 bad", IOC(0x10, 0x20), &n);

    n.flags = 0;
    n.flags2 = 0x4; /* bit2 @ +0x18 */
    try_one(fd, ctx.id, "native flags2=0x4 bad", IOC(0x10, 0x20), &n);

    n.flags = 0x4; /* bit2 @ +0x04 only */
    n.flags2 = 0;
    try_one(fd, ctx.id, "native flags=0x4 flags2=0 bad", IOC(0x10, 0x20), &n);

    n.flags = 0x4;
    n.flags2 = 0x4;
    try_one(fd, ctx.id, "native both 0x4 bad", IOC(0x10, 0x20), &n);

    n.ibdesc_addr = (uint64_t)(uintptr_t)&ib;
    n.flags = 0;
    n.flags2 = 0x4;
    try_one(fd, ctx.id, "native flags2=0x4 good ptr", IOC(0x10, 0x20), &n);

    n.flags = 0;
    n.flags2 = 0;
    try_one(fd, ctx.id, "native flags=0 good ptr", IOC(0x10, 0x20), &n);
  }

  printf("\n=== B: compat 0xc0140910 (20B) — old probe layout ===\n");
  {
    struct issueib_compat20 c;
    memset(&c, 0, sizeof(c));
    c.drawctxt_id = ctx.id;
    c.ibdesc_addr = (uint32_t)(uintptr_t)bad;
    c.numibs = 1;
    c.flags = 0;
    try_one(fd, ctx.id, "compat20 flags=0 bad", 0xc0140910, &c);

    c.flags = 0x4;
    try_one(fd, ctx.id, "compat20 flags=0x4 bad", 0xc0140910, &c);

    c.flags = 0;
    c.ibdesc_addr = (uint32_t)(uintptr_t)&ib;
    try_one(fd, ctx.id, "compat20 flags=0 good", 0xc0140910, &c);

    c.flags = 0x4;
    try_one(fd, ctx.id, "compat20 flags=0x4 good", 0xc0140910, &c);
  }

  printf("\n=== C: native size 0x18 / 0x1c / 0x24 variants with flags2 ===\n");
  {
    uint8_t buf[0x28];
    for (int sz = 0x14; sz <= 0x28; sz += 4) {
      memset(buf, 0, sizeof(buf));
      *(uint32_t *)(buf + 0) = ctx.id;
      *(uint64_t *)(buf + 8) = (uint64_t)(uintptr_t)bad;
      *(uint32_t *)(buf + 0x10) = 1;
      if (sz > 0x18)
        *(uint32_t *)(buf + 0x18) = 0x4;
      char tag[48];
      snprintf(tag, sizeof(tag), "sz=0x%02x flags2=0x4 bad", sz);
      try_one(fd, ctx.id, tag, IOC(0x10, sz), buf);
    }
  }

  ioctl(fd, IOC(0x14, 0x04), &ctx.id);
  close(fd);
  printf("\nDone. EFAULT on bad ptr ⇒ list CFU path reached.\n");
  return 0;
}
