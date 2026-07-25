#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE: ret=%d id=%u\n\n", r, ctx.id);
    if (r < 0) { close(fd); return 1; }

    /* Test SUBMIT_COMMANDS with various pointer/struct configurations */
    printf("=== Debugging EFAULT ===\n");
    
    /* Test 0: cmdlist_size=0, numcmds=0 — should succeed if only cmdlist is broken */
    {
        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("size=0,numcmds=0: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Test 1: Use stack buffer for struct + stack ibdesc */
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0, 1};
        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        /* Store as 64-bit value */
        *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x10) = 16;
        *(uint32_t*)(sbuf+0x14) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("stack ibdesc(64-bit ptr): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Test 2: Use compat cmd code (0xc02c093d) with 44-byte struct */
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0, 1};
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x04) = 0;
        *(uint32_t*)(sbuf+0x08) = (uint32_t)(uintptr_t)&ib; /* 32-bit ptr */
        *(uint32_t*)(sbuf+0x0C) = 0;  /* ??? */
        *(uint32_t*)(sbuf+0x10) = 16; /* cmdlist_size */
        *(uint32_t*)(sbuf+0x14) = 1;  /* numcmds */
        *(uint32_t*)(sbuf+0x18) = 0;  /* timestamp */
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        printf("compat cmd 44B: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Test 3: Check access_ok by reading the address first */
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0, 1};
        /* Verify the ibdesc is readable from userspace */
        volatile uint64_t test = ib.ga + ib.sw;
        (void)test;

        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x10) = 16;
        *(uint32_t*)(sbuf+0x14) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("verified ibdesc ptr: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Test 4: What if we use mmap'd buffers? */
    {
        void *ib_m = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
        void *sb_m = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
        if (ib_m == MAP_FAILED || sb_m == MAP_FAILED) {
            printf("mmap failed\n");
        } else {
            *(uint64_t*)(ib_m+0x00) = 0;   /* gpuaddr */
            *(uint64_t*)(ib_m+0x08) = 1;   /* sizedwords */
            memset(sb_m, 0, 56);
            *(uint32_t*)(sb_m+0x00) = ctx.id;
            *(uint64_t*)(sb_m+0x08) = (uint64_t)(uintptr_t)ib_m;
            *(uint32_t*)(sb_m+0x10) = 16;
            *(uint32_t*)(sb_m+0x14) = 1;
            errno = 0; r = ioctl(fd, 0xc038093d, sb_m);
            printf("mmap'd buffers: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
            munmap(ib_m, 0x1000); munmap(sb_m, 0x1000);
        }
    }

    /* Test 5: Also try writing to the ibdesc to ensure it's faulted in */
    {
        struct { uint64_t ga; uint64_t sw; } ib;
        ib.ga = 0;
        ib.sw = 1;
        /* Force page fault */
        memset(&ib, 0, sizeof(ib));
        ib.sw = 1;

        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x10) = 16;
        *(uint32_t*)(sbuf+0x14) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("faulted-in ibdesc: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
