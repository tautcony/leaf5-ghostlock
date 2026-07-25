/**
 * test_64bit.c — Test KGSL from 64-bit native path
 * Compares behavior with 32-bit compat path.
 */
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

/* 64-bit native ioctl commands */
#define SETPROP_64   KGSL_IOC(0x02, 0x18)  /* 24 bytes */
#define CREATE_64    KGSL_IOC(0x13, 0x08)  /* 8 bytes */
#define DESTROY_64   KGSL_IOC(0x14, 0x04)  /* 4 bytes */
#define ISSUEIB_64   KGSL_IOC(0x10, 0x20)  /* 32 bytes */
#define SUBMIT_64    KGSL_IOC(0x3d, 0x38)  /* 56 bytes */
#define GPUMEMID_64  KGSL_IOC(0x33, 0x20)  /* 32 bytes */
#define MAP_USER_64  KGSL_IOC(0x15, 0x30)  /* 48 bytes */

#define CTX_FLAGS 0x00000012

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }
    printf("=== 64-bit Native KGSL Test ===\nfd=%d\n\n", fd);

    /* ── SET_PROPERTY (64-bit native struct: 24 bytes) ─────── */
    printf("── SET_PROPERTY ──\n");
    /* 64-bit: type(4B), pad(4B), value_ptr(8B), sizebytes(4B), pad2(4B) = 24B */
    struct { uint32_t type; uint32_t pad; uint64_t value_ptr; uint32_t sizebytes; uint32_t pad2; } sp = {0};
    char val[256] = {0};
    uint32_t props[] = {0x6, 0x7, 0x13, 0x18, 0x1A, 0x1B, 0x20, 0x25};
    for (int i = 0; i < sizeof(props)/sizeof(props[0]); i++) {
        memset(val, 0, sizeof(val));
        sp.type = props[i]; sp.value_ptr = (uint64_t)(uintptr_t)val; sp.sizebytes = sizeof(val);
        int r = ioctl(fd, SETPROP_64, &sp);
        printf("  SETPROP 0x%02x: ret=%d errno=%d\n", props[i], r, errno);
    }

    /* ── DRAWCTXT_CREATE ────────────────────────────────────── */
    printf("\n── DRAWCTXT_CREATE ──\n");
    struct { uint32_t f; uint32_t id; } ctx = {CTX_FLAGS, 0};
    int r = ioctl(fd, CREATE_64, &ctx);
    printf("  CREATE(0x%08x): ret=%d id=%u errno=%d\n", CTX_FLAGS, r, ctx.id, errno);

    if (r < 0) {
        /* Also try without flags */
        ctx.f = 0; ctx.id = 0;
        r = ioctl(fd, CREATE_64, &ctx);
        printf("  CREATE(0x0): ret=%d id=%u errno=%d\n", r, ctx.id, errno);

        ctx.f = 0x13; ctx.id = 0;
        r = ioctl(fd, CREATE_64, &ctx);
        printf("  CREATE(0x13): ret=%d id=%u errno=%d\n", r, ctx.id, errno);

        close(fd);
        return 1;
    }
    uint32_t ctx_id = ctx.id;
    printf("  ✅ Context created! id=%u\n\n", ctx_id);

    /* ── GPUMEM_ALLOC_ID (64-bit native: 32 bytes) ────────── */
    printf("── GPUMEM_ALLOC_ID ──\n");
    /* Native 64-bit struct: id(8B), flags(4B+pad), size(8B), mmapsize(8B) = 32B */
    struct {
        uint64_t id;
        uint32_t flags;
        uint32_t pad;
        uint64_t size;
        uint64_t mmapsize;
    } mem = {0};

    uint32_t memflags[] = {
        0x10000000,                          /* USE_CPU_MAP */
        0x10000000 | (12 << 16),             /* + 4KB align */
        0x10000000 | (0 << 8),               /* + OBJECTANY */
        0x10000000 | (16 << 8) | (12 << 16),/* + COMMAND + 4KB */
    };

    uint32_t mem_id = 0; uint64_t mem_mapsize = 0;
    for (int fi = 0; fi < sizeof(memflags)/sizeof(memflags[0]); fi++) {
        memset(&mem, 0, sizeof(mem));
        mem.size = 0x10000;
        mem.flags = memflags[fi];
        errno = 0;
        r = ioctl(fd, GPUMEMID_64, &mem);
        printf("  flags=0x%08x: ret=%d id=%llu mmapsize=%llu errno=%d",
               memflags[fi], r, (unsigned long long)mem.id,
               (unsigned long long)mem.mmapsize, errno);
        if (r == 0) {
            printf(" ✅\n");
            mem_id = mem.id;
            mem_mapsize = mem.mmapsize;
            break;
        }
        printf(" (%s)\n", strerror(errno));
    }

    /* ── RB_ISSUEIBCMDS (64-bit native: 32 bytes) ────────── */
    printf("\n── RB_ISSUEIBCMDS ──\n");
    /* Native 64-bit struct: drawctxt_id(4B), flags(4B), ibdesc_addr(8B),
       numibs(4B), pad(4B), timestamp(4B), pad2(4B) = 32B */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } ibdesc = {0, 0};
    struct {
        uint32_t drawctxt_id; uint32_t flags;
        uint64_t ibdesc_addr;
        uint32_t numibs; uint32_t pad;
        uint32_t timestamp; uint32_t pad2;
    } cmd = {ctx_id, 0, (uint64_t)(uintptr_t)&ibdesc, 0, 0, 0, 0};

    /* First try with numibs=0 to test basic dispatch */
    r = ioctl(fd, ISSUEIB_64, &cmd);
    printf("  numibs=0: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");

    /* With numibs=1, gpuaddr=0 */
    cmd.numibs = 1;
    r = ioctl(fd, ISSUEIB_64, &cmd);
    printf("  numibs=1,gpuaddr=0: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");

    /* With "reasonable" gpuaddr */
    ibdesc.gpuaddr = 0x10000000ULL; ibdesc.sizedwords = 1;
    r = ioctl(fd, ISSUEIB_64, &cmd);
    printf("  numibs=1,gpuaddr=0x10000000: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");

    /* If we have mmap'd memory, use its address */
    if (mem_id) {
        void *gmap = mmap(0, mem_mapsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (gmap != MAP_FAILED) {
            printf("\n  mmap'd GPU mem at %p\n", gmap);
            *(uint32_t*)gmap = 0;
            ibdesc.gpuaddr = (uint64_t)(uintptr_t)gmap;
            r = ioctl(fd, ISSUEIB_64, &cmd);
            printf("  numibs=1,gpuaddr=mapped: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");
            munmap(gmap, mem_mapsize);
        }
    }

    /* ── SUBMIT_COMMANDS ────────────────────────────────────── */
    printf("\n── SUBMIT_COMMANDS ──\n");
    uint8_t sbuf[56] = {0};
    *(uint32_t*)&sbuf[0] = ctx_id;  /* context_id */
    *(uint32_t*)&sbuf[20] = 1;      /* numcmds */
    r = ioctl(fd, SUBMIT_64, sbuf);
    printf("  ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");

    /* ── MAP_USER_MEM ──────────────────────────────────────── */
    printf("\n── MAP_USER_MEM ──\n");
    void *umem = mmap(0, 0x10000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (umem != MAP_FAILED) {
        struct {
            uint32_t memtype; uint32_t pad;
            uint64_t hostptr;
            uint64_t len;
            uint64_t offset;
            uint64_t gpuaddr;
        } map = {0};
        map.memtype = 4; /* KGSL_USER_MEM_TYPE_ADDR */
        map.hostptr = (uint64_t)(uintptr_t)umem;
        map.len = 0x1000;
        r = ioctl(fd, MAP_USER_64, &map);
        printf("  type=ADDR: ret=%d gpuaddr=0x%llx errno=%d (%s)\n",
               r, (unsigned long long)map.gpuaddr, errno, strerror(errno));
        munmap(umem, 0x10000);
    }

    /* Cleanup */
    printf("\n── Cleanup ──\n");
    r = ioctl(fd, DESTROY_64, &ctx_id);
    printf("  DESTROY: ret=%d errno=%d\n", r, errno);
    close(fd);
    return 0;
}
