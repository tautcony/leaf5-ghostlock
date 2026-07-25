/**
 * test_kgsl_sequence.c — Try full KGSL init sequence including memory allocation
 *
 * Based on compat ioctl table analysis:
 * - GPUMEM_ALLOC_ID (0x33): compat available (0xc0140933, 20B)
 * - MAP_USER_MEM (0x15): compat available (0xc01c0915, 28B)
 * - GPUMEM_ALLOC (0x20): NO compat handler! Must use _ID variant.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define KGSL_DEVICE "/dev/kgsl-3d0"

int main(void) {
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }
    printf("fd=%d\n\n", fd);

    /* ── Step 1: Set device properties (MMU enable etc.) ──────── */
    printf("── Step 1: Device properties ──\n");
    struct { uint32_t type; uint32_t value_ptr; uint32_t sizebytes; } sp = {0};
    char valbuf[256] = {0};

    uint32_t init_props[] = {0x6, 0x7, 0x13, 0x18, 0x1A, 0x1B, 0x20, 0x25};
    const char *pnames[] = {[0x6]="MMU", [0x7]="INT", [0x13]="UCHE", [0x18]="BITNESS",
                            [0x1A]="MINACC", [0x1B]="UBWC", [0x20]="QTIMER", [0x25]="SPEEDBIN"};
    for (int i = 0; i < sizeof(init_props)/sizeof(init_props[0]); i++) {
        memset(valbuf, 0, sizeof(valbuf));
        sp.type = init_props[i];
        sp.value_ptr = (uint32_t)(uintptr_t)valbuf;
        sp.sizebytes = sizeof(valbuf);
        int r = ioctl(fd, 0xc00c0902, &sp);
        printf("  SETPROP %-8s (0x%02x): ret=%d errno=%d\n",
               pnames[init_props[i]] ? pnames[init_props[i]] : "?", init_props[i], r, errno);
    }

    /* ── Step 2: Allocate GPU memory ──────────────────────────── */
    printf("\n── Step 2: GPU memory allocation ──\n");

    /* GPUMEM_ALLOC_ID compat: 0xc0140933, 20 bytes
     * struct kgsl_gpumem_alloc_id {
     *     uint64_t size;        // +0x00 (8B)
     *     uint32_t flags;       // +0x08 (4B)
     *     uint32_t id;          // +0x0C (4B) output
     *     uint32_t mmapsize;    // +0x10 (4B) output
     *     // total: 20 bytes
     * };
     */
    struct {
        uint64_t size;
        uint32_t flags;
        uint32_t id;
        uint32_t mmapsize;
    } alloc = {0};

    /* Try with different sizes and flags */
    uint64_t sizes[] = {0x1000, 0x10000, 0x100000, 0x400000};
    uint32_t flag_opts[] = {
        0,                              /* default */
        0x00001000,                     /* KGSL_MEMFLAGS_USE_CPU_MAP? */
        0x00000001,                     /* KGSL_MEMFLAGS_SECURE? */
        0x00000002,                     /* KGSL_MEMFLAGS_CONTIGUOUS? */
    };

    uint32_t mem_id = 0;
    uint64_t mem_size = 0;

    for (int si = 0; si < sizeof(sizes)/sizeof(sizes[0]) && !mem_id; si++) {
        for (int fi = 0; fi < sizeof(flag_opts)/sizeof(flag_opts[0]) && !mem_id; fi++) {
            memset(&alloc, 0, sizeof(alloc));
            alloc.size = sizes[si];
            alloc.flags = flag_opts[fi];
            errno = 0;
            int r = ioctl(fd, 0xc0140933, &alloc);
            if (r == 0) {
                printf("  GPUMEM_ALLOC_ID size=0x%llx flags=0x%08x: SUCCESS id=%u mmapsize=%u\n",
                       (unsigned long long)alloc.size, alloc.flags, alloc.id, alloc.mmapsize);
                mem_id = alloc.id;
                mem_size = alloc.size;
                break;
            }
            if (si == 0 && fi == 0) {
                /* Print first attempt */
                printf("  GPUMEM_ALLOC_ID size=0x%llx flags=0x%08x: ret=%d errno=%d (%s)\n",
                       (unsigned long long)alloc.size, alloc.flags, r, errno, strerror(errno));
            }
        }
    }

    if (!mem_id) {
        printf("  All GPUMEM_ALLOC_ID attempts failed!\n");
    }

    /* ── Step 2b: MAP_USER_MEM ────────────────────────────────── */
    printf("\n── Step 2b: Map user memory ──\n");
    /* MAP_USER_MEM compat: 0xc01c0915, 28 bytes */
    struct {
        uint32_t memtype;       /* +0x00: KGSL_USER_MEM_TYPE_* */
        uint32_t padding;       /* +0x04 */
        uint32_t len;           /* +0x08 */
        uint32_t hostptr;       /* +0x0C: 32-bit user pointer */
        uint32_t offset;        /* +0x10 */
        uint32_t gpuaddr_lo;    /* +0x14: output - lower 32 bits */
        uint32_t gpuaddr_hi;    /* +0x18: output - upper 32 bits */
    } map_mem = {0};

    /* Allocate some memory to map */
    void *user_mem = mmap(0, 0x10000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (user_mem != MAP_FAILED) {
        printf("  user_mem allocated at %p\n", user_mem);

        /* KGSL_USER_MEM_TYPE_ADDR = 4 (Ion? PMEM?) */
        /* Try different memory types */
        uint32_t mem_types[] = {0, 1, 2, 3, 4, 5, 6};
        for (int t = 0; t < sizeof(mem_types)/sizeof(mem_types[0]); t++) {
            memset(&map_mem, 0, sizeof(map_mem));
            map_mem.memtype = mem_types[t];
            map_mem.len = 0x10000;
            map_mem.hostptr = (uint32_t)(uintptr_t)user_mem;
            errno = 0;
            int r = ioctl(fd, 0xc01c0915, &map_mem);
            if (r == 0) {
                printf("  MAP_USER_MEM type=%d: SUCCESS gpuaddr=0x%08x%08x\n",
                       mem_types[t], map_mem.gpuaddr_hi, map_mem.gpuaddr_lo);
                break;
            }
            if (t == 0) {
                printf("  MAP_USER_MEM type=0: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
            }
        }
        munmap(user_mem, 0x10000);
    } else {
        printf("  mmap failed: %d\n", errno);
    }

    /* ── Step 3: Try context creation again ────────────────────── */
    printf("\n── Step 3: DRAWCTXT_CREATE ──\n");
    struct { uint32_t flags; uint32_t id; } c = {0x00100000, 0};  /* TYPE_GL */
    int r = ioctl(fd, 0xc0080913, &c);
    printf("  CREATE(TYPE_GL): ret=%d id=%u errno=%d (%s)\n", r, c.id, errno, strerror(errno));

    /* ── Step 4: Also try regular GPUMEM_ALLOC (64-bit path via compat_trick) ── */
    printf("\n── Step 4: Other ioctls ──\n");

    /* Try GPUOBJ_ALLOC - might be needed for newer KGSL versions */
    /* nr=0x35: compat_cmd=0xc0080935 sz=8 */
    {
        struct { uint32_t id; uint32_t flags; } obj = {0, 0};
        r = ioctl(fd, 0xc0080935, &obj);
        printf("  GPUOBJ_ALLOC?(0x35): ret=%d id=%u errno=%d\n", r, obj.id, errno);
    }

    /* Try CMDSTREAM_FREEMEMONTIMESTAMP_CTXTID (nr=0x17) */
    /* This might set up timestamp/memory for a context */
    {
        struct { uint32_t context_id; uint32_t timestamp; uint32_t type; uint32_t len; } ts = {0, 0, 0, 0};
        r = ioctl(fd, 0x40100917, &ts);
        printf("  FREEMEMONTIMESTAMP_CTXTID(0x17): ret=%d errno=%d\n", r, errno);
    }

    close(fd);
    return 0;
}
