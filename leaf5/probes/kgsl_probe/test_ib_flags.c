#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define IOC(nr,sz) (((uint32_t)3<<30)|(((uint32_t)(sz))<<16)|(((uint32_t)0x09)<<8)|((uint32_t)(nr)))

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, IOC(0x13, 0x08), &ctx);
    printf("CREATE: ret=%d id=%u\n\n", r, ctx.id);
    if (r < 0) { close(fd); return 1; }

    /* Try ALL flags in issueibcmds (compat: 0xc0140910, 20 bytes) */
    printf("=== RB_ISSUEIBCMDS flag scan ===\n");
    struct { uint64_t ga; uint64_t sw; } ib = {0x0, 0x1}; /* minimal ibdesc */
    
    /* Define known KGSL context flags from msm_kgsl.h */
    uint32_t ib_flags[] = {
        0x00000000,
        0x00000001,  /* KGSL_CONTEXT_SAVE_GMEM */
        0x00000002,  /* KGSL_CONTEXT_NO_GMEM_ALLOC */
        0x00000004,  /* KGSL_CONTEXT_SUBMIT_IB_LIST */
        0x00000008,  /* KGSL_CONTEXT_CTX_SWITCH */
        0x00000010,  /* KGSL_CONTEXT_PREAMBLE */
        0x00000020,  /* KGSL_CONTEXT_TRASH_STATE */
        0x00000040,  /* KGSL_CONTEXT_PER_CONTEXT_TS */
        0x00000100,  /* KGSL_CONTEXT_END_OF_FRAME */
        0x00000400,  /* KGSL_CONTEXT_SYNC */
        0x00000800,  /* KGSL_CONTEXT_PWR_CONSTRAINT */
        0x00010000,  /* KGSL_CONTEXT_IFH_NOP */
        0x00020000,  /* KGSL_CONTEXT_SECURE */
        0x10000000,  /* KGSL_CONTEXT_INVALIDATE_ON_FAULT */
        0x00000004 | 0x00000008,  /* SUBMIT_IB_LIST | CTX_SWITCH */
        0x00000004 | 0x00000010,  /* SUBMIT_IB_LIST | PREAMBLE */
    };

    int success = 0;
    for (int fi = 0; fi < sizeof(ib_flags)/sizeof(ib_flags[0]); fi++) {
        struct {
            uint32_t ctx_id; uint32_t flags;
            uint32_t ibdesc_addr; uint32_t ts; uint32_t numibs;
        } cmd = {ctx.id, ib_flags[fi], (uint32_t)(uintptr_t)&ib, 0, 1};
        
        errno = 0;
        r = ioctl(fd, 0xc0140910, &cmd);
        if (r == 0 || errno != 22) {
            printf("  flags=0x%08x: ret=%d errno=%d %s\n", ib_flags[fi], r, errno,
                   r==0?"✅ SUCCESS!":strerror(errno));
            if (r == 0) success = 1;
        }
    }
    if (!success) printf("  (all EINVAL)\n");

    /* Also try 64-bit native issueibcmds with different flags */
    printf("\n=== RB_ISSUEIBCMDS 64-bit flag scan ===\n");
    for (int fi = 0; fi < sizeof(ib_flags)/sizeof(ib_flags[0]); fi++) {
        struct {
            uint32_t ctx_id; uint32_t flags;
            uint64_t ibdesc_addr;
            uint32_t numibs; uint32_t pad1;
            uint32_t ts; uint32_t pad2;
        } cmd64 = {ctx.id, ib_flags[fi], (uint64_t)(uintptr_t)&ib, 1, 0, 0, 0};
        
        errno = 0;
        r = ioctl(fd, IOC(0x10, 0x20), &cmd64);
        if (r == 0 || errno != 22) {
            printf("  flags=0x%08x: ret=%d errno=%d %s\n", ib_flags[fi], r, errno,
                   r==0?"✅ SUCCESS!":strerror(errno));
            if (r == 0) success = 1;
        }
    }
    if (!success) printf("  (all EINVAL)\n");

    /* Try GPU_AUX_COMMAND (nr=0x57) — another path that might reach CFU */
    printf("\n=== GPU_AUX_COMMAND (0x57) ===\n");
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, IOC(0x57, 0x14), buf);
        printf("  64-bit: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        
        /* 32-bit compat */
        errno = 0; r = ioctl(fd, 0xc0140957, buf);
        printf("  compat: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Try GPU_COMMAND (nr=0x3e) */
    printf("\n=== GPU_COMMAND (0x3e) ===\n");
    {
        uint8_t buf[256] = {0};
        *(uint32_t*)&buf[0] = ctx.id;
        errno = 0; r = ioctl(fd, IOC(0x3e, 0x38), buf);
        printf("  ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    }

    ioctl(fd, IOC(0x14, 0x04), &ctx.id);
    close(fd);
    return 0;
}
