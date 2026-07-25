#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define F_SETPIPE_SZ 1031

int main(void) {
    int p[2];
    if (pipe(p) < 0) { printf("pipe: %d\n", errno); return 1; }
    
    for (int slots = 2; slots <= 256; slots *= 2) {
        int sz = slots * 4096;
        errno = 0;
        int r = fcntl(p[0], F_SETPIPE_SZ, sz);
        printf("SETPIPE_SZ(%d*4K=%d): ret=%d errno=%d (%s)\n",
               slots, sz, r, errno, r<0?strerror(errno):"OK");
        if (r == 0) break;
    }
    
    close(p[0]); close(p[1]);
    return 0;
}
