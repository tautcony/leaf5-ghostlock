#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

/* 64-bit native ioctls */
#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d\n\n", fd);

    /* Try GPUMEM_ALLOC (nr=0x20) — the non-ID version */
    /* Native: 0xc0180920, 24 bytes */
    /* struct kgsl_gpumem_alloc { unsigned long gpuaddr; unsigned int flags; 
       unsigned int padding; unsigned long size; } */
    
    printf("=== GPUMEM_ALLOC (nr=0x20, 24B) ===\n");
    struct {
        uint64_t gpuaddr;    /* output */
        uint32_t flags;
        uint32_t pad;
        uint64_t size;
    } alloc = {0};

    uint64_t sizes[] = {0x1000, 0x10000, 0x80000, 0x100000};
    uint32_t flags[] = {
        0,
        0x10000000,  /* USE_CPU_MAP */
        0x10000000 | (12 << 16),  /* +4KB align */
    };

    for (int si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++) {
        for (int fi = 0; fi < sizeof(flags)/sizeof(flags[0]); fi++) {
            memset(&alloc, 0, sizeof(alloc));
            alloc.size = sizes[si];
            alloc.flags = flags[fi];
            errno = 0;
            int r = ioctl(fd, IOC(0x20, 0x18), &alloc);
            if (r == 0) {
                printf("  ✅ size=0x%llx flags=0x%08x: gpuaddr=0x%llx\n",
                       (unsigned long long)alloc.size, alloc.flags,
                       (unsigned long long)alloc.gpuaddr);
                goto found;
            }
            if (si == 0 && fi == 0)
                printf("  size=0x%llx flags=0x%08x: ret=%d errno=%d (%s)\n",
                       (unsigned long long)alloc.size, alloc.flags, r, errno, strerror(errno));
        }
    }
    printf("  All GPUMEM_ALLOC failed\n");
found:

    /* Try different ioctl sizes for GPUMEM_ALLOC */
    printf("\n=== GPUMEM_ALLOC size variants ===\n");
    for (int sz = 8; sz <= 48; sz += 8) {
        uint8_t buf[48] = {0};
        *(uint64_t*)&buf[0] = 0;  /* gpuaddr out */
        *(uint32_t*)&buf[8] = 0x10000000;  /* flags */
        *(uint64_t*)&buf[16] = 0x1000;  /* size */
        errno = 0;
        int r = ioctl(fd, IOC(0x20, sz), buf);
        if (sz == 24 || errno != 25)  /* print interesting ones */
            printf("  sz=%d: ret=%d errno=%d %s\n", sz, r, errno, sz==24?"(native)":"");
    }

    /* Try mmap on kgsl device with 0 offset (some GPUs allow this) */
    printf("\n=== mmap tests ===\n");
    for (int off = 0; off < 4; off++) {
        errno = 0;
        void *p = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off * 0x1000);
        printf("  mmap(off=0x%x): %p errno=%d\n", off*0x1000, p, errno);
        if (p != MAP_FAILED) munmap(p, 0x1000);
    }

    close(fd);
    return 0;
}
