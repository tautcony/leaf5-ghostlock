#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    /* Try ALL compat ioctls to find one that works for memory/init */
    /* From the compat table, try each non-zero entry */
    struct {
        uint32_t nr;
        uint32_t cmd;
        uint32_t size;
        const char *name;
    } compat_ioctls[] = {
        {0x02, 0xc00c0902, 12, "SETPROPERTY"},
        {0x07, 0x400c0907, 12, "WAITTIMESTAMP_CTXTID"},
        {0x10, 0xc0140910, 20, "RB_ISSUEIBCMDS"},
        {0x13, 0xc0080913, 8,  "DRAWCTXT_CREATE"},
        {0x14, 0x40040914, 4,  "DRAWCTXT_DESTROY"},
        {0x15, 0xc01c0915, 28, "MAP_USER_MEM"},
        {0x16, 0xc00c0916, 12, "CMDSTREAM_READTIMESTAMP_CTXTID"},
        {0x17, 0x40100917, 16, "CMDSTREAM_FREEMEMONTIMESTAMP_CTXTID"},
        {0x21, 0x40040921, 4,  "GPUMEM_FREE_ID?"},
        {0x24, 0x40040924, 4,  "GPUMEM_GET_INFO?"},
        {0x2f, 0xc00c092f, 12, "SHAREDMEM_FLUSH_CACHE"},
        {0x32, 0x400c0932, 12, "UNKNOWN_0x32"},
        {0x33, 0xc0140933, 20, "GPUMEM_ALLOC_ID"},
        {0x34, 0xc01c0934, 28, "GPUMEM_SYNC_CACHE"},
        {0x35, 0xc0080935, 8,  "GPUOBJ_ALLOC?"},
        {0x36, 0xc0280936, 40, "GPUMEM_SYNC_CACHE_BULK"},
        {0x37, 0x40140937, 20, "PERFCOUNTER_QUERY?"},
        {0x3c, 0xc014093c, 20, "UNKNOWN_0x3c"},
        {0x3d, 0xc02c093d, 44, "SUBMIT_COMMANDS"},
    };

    printf("=== Testing all compat ioctls (empty/zero structs) ===\n");
    for (int i = 0; i < sizeof(compat_ioctls)/sizeof(compat_ioctls[0]); i++) {
        uint8_t buf[256] = {0};
        errno = 0;
        int r = ioctl(fd, compat_ioctls[i].cmd, buf);
        if (errno != 22 || r == 0) {  /* show non-EINVAL results */
            printf("  [0x%02x] %-35s cmd=0x%08x: ret=%d errno=%d (%s)\n",
                   compat_ioctls[i].nr, compat_ioctls[i].name,
                   compat_ioctls[i].cmd, r, errno, r<0?strerror(errno):"OK ✅");
        }
    }

    /* Now with a valid context */
    printf("\n=== With valid context (create first) ===\n");
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("CREATE: ret=%d id=%u\n", r, ctx.id);
    if (r < 0) { close(fd); return 1; }

    /* Try various ioctls that might need a context */
    /* FREEMEMONTIMESTAMP with ctx_id */
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, 0x40100917, buf);
        printf("FREEMEMONTIMESTAMP(ctx=%u): ret=%d errno=%d (%s)\n", ctx.id, r, errno, strerror(errno));
    }

    /* SETPROP with CONTEXT_PROPERTY */
    {
        struct { uint32_t t; uint32_t v; uint32_t s; } sp = {0};
        char vb[256] = {0};
        *(uint32_t*)vb = ctx.id;  /* context id for property */
        sp.t = 0x28;  /* CONTEXT_PROPERTY */
        sp.v = (uint32_t)(uintptr_t)vb;
        sp.s = 4;
        errno = 0; r = ioctl(fd, 0xc00c0902, &sp);
        printf("SETPROP(CONTEXT_PROPERTY, ctx=%u): ret=%d errno=%d (%s)\n", ctx.id, r, errno, strerror(errno));
    }

    /* TIMESTAMP_EVENT */
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, 0xc0140916, buf);
        printf("CMDSTREAM_READTIMESTAMP_CTXTID: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Try the non-compat 64-bit ioctls from 64-bit process */
    /* GPUOBJ_ALLOC - newer API */
    {
        uint8_t buf[256] = {0};
        errno = 0; r = ioctl(fd, IOC(0x35, 0x20), buf);
        printf("GPUOBJ_ALLOC(64-bit,0x20): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        errno = 0; r = ioctl(fd, IOC(0x35, 0x10), buf);
        printf("GPUOBJ_ALLOC(64-bit,0x10): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        errno = 0; r = ioctl(fd, IOC(0x35, 0x08), buf);
        printf("GPUOBJ_ALLOC(64-bit,0x08): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* GPUOBJ_IMPORT */
    {
        uint8_t buf[256] = {0};
        errno = 0; r = ioctl(fd, IOC(0x36, 0x40), buf);
        printf("GPUOBJ_IMPORT: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* SYNCSOURCE - maybe this works? */
    {
        uint8_t buf[256] = {0};
        errno = 0; r = ioctl(fd, IOC(0x3e, 0x10), buf);
        printf("SYNCSOURCE_CREATE: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
    close(fd);
    return 0;
}
