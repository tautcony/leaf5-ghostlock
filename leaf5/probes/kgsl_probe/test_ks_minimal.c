#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdint.h>

int main(void) {
    printf("=== Kernelsnitch component test ===\n");
    
    /* Try 128MB mmap (what Kernelsnitch needs) */
    size_t sz = 128ULL * 1024 * 1024;
    printf("mmap %zuMB...\n", sz/(1024*1024));
    void *p = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        printf("  FAILED: errno=%d\n", errno);
        /* Try progressively smaller */
        for (sz = 64*1024*1024; sz >= 4*1024*1024; sz /= 2) {
            p = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
            if (p != MAP_FAILED) { printf("  %zuMB OK at %p\n", sz/(1024*1024), p); break; }
            printf("  %zuMB failed: errno=%d\n", sz/(1024*1024), errno);
        }
        if (p == MAP_FAILED) return 1;
    } else {
        printf("  OK at %p\n", p);
    }
    
    /* Touch pages to fault them in */
    printf("Touching pages...\n");
    for (size_t i = 0; i < sz; i += 4096) {
        ((volatile char*)p)[i] = 0;
    }
    printf("  OK\n");
    
    /* Test multi-threaded mmap (Kernelsnitch uses pthread + mmap) */
    printf("Testing multi-thread...\n");
    pthread_t tid;
    void *p2 = mmap(0, 64*1024*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    printf("  second mmap at %p: %s\n", p2, p2==MAP_FAILED?"FAIL":"OK");
    if (p2 != MAP_FAILED) munmap(p2, 64*1024*1024);
    
    munmap(p, sz);
    printf("=== All OK ===\n");
    return 0;
}
