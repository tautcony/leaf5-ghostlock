#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int fd[2];

    printf("=== Pre-mmap pipe test ===\n");
    for (int i = 0; i < 3; i++) {
        pipe(fd);
        int ret = fcntl(fd[0], 1031, 8192);
        printf("  pipe %d: ret=%d %s\n", i, ret, ret<0?strerror(errno):"OK");
        close(fd[0]); close(fd[1]);
    }

    printf("\n=== After 64GB mmap ===\n");
    void *p = mmap(NULL, 64ULL*1024*1024*1024, PROT_READ|PROT_WRITE,
                   MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
    printf("mmap(64GB)=%p %s\n", p, p==MAP_FAILED?strerror(errno):"OK");

    for (int i = 0; i < 3; i++) {
        pipe(fd);
        int ret = fcntl(fd[0], 1031, 8192);
        printf("  pipe %d: ret=%d %s\n", i, ret, ret<0?strerror(errno):"OK");
        close(fd[0]); close(fd[1]);
    }

    printf("\n=== After 100 child processes ===\n");
    for (int i = 0; i < 100; i++) {
        pid_t c = fork();
        if (c == 0) { usleep(50000); _exit(0); }
    }
    for (int i = 0; i < 100; i++) waitpid(-1, NULL, 0);

    for (int i = 0; i < 3; i++) {
        pipe(fd);
        int ret = fcntl(fd[0], 1031, 8192);
        printf("  pipe %d: ret=%d %s\n", i, ret, ret<0?strerror(errno):"OK");
        close(fd[0]); close(fd[1]);
    }

    printf("\n=== After mmap+madvise+DONTNEED ===\n");
    if (p != MAP_FAILED) {
        madvise(p, 64ULL*1024*1024*1024, MADV_DONTNEED);
        for (int i = 0; i < 3; i++) {
            pipe(fd);
            int ret = fcntl(fd[0], 1031, 8192);
            printf("  pipe %d: ret=%d %s\n", i, ret, ret<0?strerror(errno):"OK");
            close(fd[0]); close(fd[1]);
        }
        munmap(p, 64ULL*1024*1024*1024);
    }

    printf("\n=== After cleanup ===\n");
    for (int i = 0; i < 3; i++) {
        pipe(fd);
        int ret = fcntl(fd[0], 1031, 8192);
        printf("  pipe %d: ret=%d %s\n", i, ret, ret<0?strerror(errno):"OK");
        close(fd[0]); close(fd[1]);
    }
    return 0;
}
