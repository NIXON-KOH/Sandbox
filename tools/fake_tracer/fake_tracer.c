#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Original libc functions */
static int (*real_open)(const char *path, int flags, mode_t mode) = NULL;
static int (*real_openat)(int dirfd, const char *path, int flags, mode_t mode) = NULL;
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static int (*real_close)(int fd) = NULL;
static FILE *(*real_fopen)(const char *path, const char *mode) = NULL;
static char *(*real_fgets)(char *s, int size, FILE *stream) = NULL;
static int (*real_fclose)(FILE *stream) = NULL;   // <-- added

/* Track file descriptors */
#define MAX_FDS 512
static int traced_fds[MAX_FDS];
static int traced_fd_count = 0;

/* Track FILE* streams */
#define MAX_STREAMS 64
static FILE *traced_streams[MAX_STREAMS];
static int traced_stream_count = 0;

/* Helper: check if path is /proc/self/status or /proc/<pid>/status */
static int is_status_file(const char *path) {
    if (!path) return 0;
    if (strcmp(path, "/proc/self/status") == 0) return 1;
    if (strstr(path, "/proc/") == path && strstr(path, "/status") != NULL) {
        return 1;
    }
    return 0;
}

/* Lazy initialisation of function pointers */
static void init_funcs(void) {
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!real_fgets) real_fgets = dlsym(RTLD_NEXT, "fgets");
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
}

static void add_fd(int fd) {
    if (fd < 0 || traced_fd_count >= MAX_FDS) return;
    for (int i = 0; i < traced_fd_count; i++) {
        if (traced_fds[i] == fd) return;
    }
    traced_fds[traced_fd_count++] = fd;
}

static void remove_fd(int fd) {
    for (int i = 0; i < traced_fd_count; i++) {
        if (traced_fds[i] == fd) {
            for (int j = i; j < traced_fd_count - 1; j++) {
                traced_fds[j] = traced_fds[j+1];
            }
            traced_fd_count--;
            break;
        }
    }
}

static int is_traced_fd(int fd) {
    for (int i = 0; i < traced_fd_count; i++) {
        if (traced_fds[i] == fd) return 1;
    }
    return 0;
}

/* --- Hooked functions --- */

int open(const char *path, int flags, ...) {
    init_funcs();
    // We ignore the variadic mode argument because we never open /proc/self/status with O_CREAT.
    int fd = real_open(path, flags, 0);
    if (fd >= 0 && is_status_file(path)) {
        add_fd(fd);
    }
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...) {
    init_funcs();
    int fd = real_openat(dirfd, path, flags, 0);
    if (fd >= 0 && is_status_file(path)) {
        add_fd(fd);
    }
    return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
    init_funcs();
    ssize_t ret = real_read(fd, buf, count);
    if (ret > 0 && is_traced_fd(fd)) {
        char *data = (char *)buf;
        char *p = strstr(data, "TracerPid:");
        if (p) {
            p += 10; // skip "TracerPid:"
            while (*p == ' ' || *p == '\t') p++;
            while (*p >= '0' && *p <= '9') {
                *p = '0';
                p++;
            }
        }
    }
    return ret;
}

int close(int fd) {
    init_funcs();
    remove_fd(fd);
    return real_close(fd);
}

FILE *fopen(const char *path, const char *mode) {
    init_funcs();
    FILE *fp = real_fopen(path, mode);
    if (fp && is_status_file(path) && traced_stream_count < MAX_STREAMS) {
        traced_streams[traced_stream_count++] = fp;
    }
    return fp;
}

char *fgets(char *s, int size, FILE *stream) {
    init_funcs();
    char *ret = real_fgets(s, size, stream);
    if (ret && stream) {
        int is_tracked = 0;
        for (int i = 0; i < traced_stream_count; i++) {
            if (traced_streams[i] == stream) {
                is_tracked = 1;
                break;
            }
        }
        if (is_tracked) {
            char *p = strstr(s, "TracerPid:");
            if (p) {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
                while (*p >= '0' && *p <= '9') {
                    *p = '0';
                    p++;
                }
            }
        }
    }
    return ret;
}

int fclose(FILE *stream) {
    init_funcs();
    for (int i = 0; i < traced_stream_count; i++) {
        if (traced_streams[i] == stream) {
            for (int j = i; j < traced_stream_count - 1; j++) {
                traced_streams[j] = traced_streams[j+1];
            }
            traced_stream_count--;
            break;
        }
    }
    return real_fclose(stream);
}