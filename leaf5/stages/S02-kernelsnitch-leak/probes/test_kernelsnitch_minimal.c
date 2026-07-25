#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>

/* Minimal Kernelsnitch test — isolate the crash */
#define FUTEX_SZ (64ULL<<20)  /* 64MB — much smaller for testing */

static long kfutex(unsigned int *uaddr, int op, unsigned int val,
                   const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

int main(void) {
    printf("=== Minimal Kernelsnitch test ===\n");
    
    /* Step 1: Try basic large mmap */
    printf("mmap 64MB...\n");
    void *p = mmap(0, FUTEX_SZ, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        printf("  FAILED: errno=%d (%s)\n", errno, strerror(errno));
        /* Try smaller */
        p = mmap(0, 16*1024*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
        if (p == MAP_FAILED) {
            printf("  16MB also failed: errno=%d\n", errno);
            /* Try even smaller */
            p = mmap(0, 4*1024*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
            if (p == MAP_FAILED) {
                printf("  4MB also failed!\n");
                return 1;
            }
        }
    }
    printf("  OK at %p\n", p);
    
    /* Step 2: Test futex on the mmap'd memory (non-blocking) */
    printf("Testing futex...\n");
    unsigned int *futex_addr = (unsigned int*)p;
    *futex_addr = 1; /* mismatch → WAIT returns immediately (EAGAIN) */
    errno = 0;
    long r = kfutex(futex_addr, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    printf("  FUTEX_WAIT (val mismatch): ret=%ld errno=%d\n", r, errno);

    *futex_addr = 0;
    r = kfutex(futex_addr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    printf("  FUTEX_WAKE: ret=%ld errno=%d\n", r, errno);
    
    /* Step 3: Test the collision measurement */
    printf("Testing collision measurement...\n");
    unsigned int *futex2 = (unsigned int*)((char*)p + 4096);
    *futex2 = 0;
    r = kfutex(futex2, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
    printf("  measure (wake 0 waiters): ret=%ld errno=%d\n", r, errno);
    
    munmap(p, FUTEX_SZ);
    printf("=== Basic Kernelsnitch components OK ===\n");
    return 0;
}
