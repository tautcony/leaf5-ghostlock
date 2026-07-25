#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE id=%u\n\n", ctx.id);
    if (r < 0) { close(fd); return 1; }

    struct { uint64_t ga; uint64_t sw; } ib = {0, 1};

    /* Test: does handler actually validate fields? */
    printf("=== Validation tests ===\n");

    /* Baseline: known-working layout */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x18) = 16;
        *(uint32_t*)(sbuf+0x1c) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("baseline(num=1,sz=16): ret=%d errno=%d %s\n", r, errno, r==0?"OK":"");
    }

    /* numcmds=0 — should be no-op */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x18) = 16;
        *(uint32_t*)(sbuf+0x1c) = 0;  /* numcmds=0 */
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("numcmds=0: ret=%d errno=%d %s\n", r, errno, r==0?"OK":"");
    }

    /* numcmds=999—should fail validation */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x18) = 16;
        *(uint32_t*)(sbuf+0x1c) = 999;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("numcmds=999: ret=%d errno=%d %s\n", r, errno, r==0?"OK(no validation!)":"");
    }

    /* cmdlist_size=0 — should fail */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x18) = 0;  /* size=0 */
        *(uint32_t*)(sbuf+0x1c) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("size=0: ret=%d errno=%d %s\n", r, errno, r==0?"OK":"");
    }

    /* cmdlist=NULL — should get EFAULT */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        /* cmdlist ptr LEFT AS 0 (NULL) */
        *(uint32_t*)(sbuf+0x18) = 16;
        *(uint32_t*)(sbuf+0x1c) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("cmdlist=NULL: ret=%d errno=%d %s\n", r, errno, r==0?"OK(suspicious!)":"");
    }

    /* Wrong context ID */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = 99999;  /* invalid ctx */
        *(uint64_t*)(sbuf+0x10) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x18) = 16;
        *(uint32_t*)(sbuf+0x1c) = 1;
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("ctx=99999: ret=%d errno=%d %s\n", r, errno, r==0?"OK(bad!)":"");
    }

    /* All-zero struct — should fail with EINVAL */
    {
        uint8_t sbuf[56] = {0};
        errno = 0; r = ioctl(fd, 0xc038093d, sbuf);
        printf("all-zero: ret=%d errno=%d %s\n", r, errno, r==0?"OK":"");
    }

    /* Also: use the CORRECT compat command (0xc02c093d) with proper 44-byte struct */
    printf("\n=== Compat path (0xc02c093d) for comparison ===\n");
    {
        uint8_t sbuf[44] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x08) = (uint32_t)(uintptr_t)&ib;  /* 32-bit ptr */
        *(uint32_t*)(sbuf+0x10) = 16;
        *(uint32_t*)(sbuf+0x14) = 1;
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        printf("compat: ret=%d errno=%d %s\n", r, errno, r==0?"OK":"");
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
