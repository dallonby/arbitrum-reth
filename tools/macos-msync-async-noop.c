// Test shim for MDBX's no-sync modes on macOS.
//
// libmdbx treats every non-Linux platform as requiring an mmap "jolt", so even
// MDBX_UTTERLY_NOSYNC calls msync(MS_ASYNC) over the full used mapping on each
// commit. macOS already tracks dirty MAP_SHARED pages. Skip only that async
// hint; explicit/durable MS_SYNC calls still go to libc unchanged.

#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int replacement_msync(void *address, size_t length, int flags) {
    if ((flags & MS_ASYNC) != 0 && (flags & MS_SYNC) == 0) {
        static int reported;
        if (__sync_bool_compare_and_swap(&reported, 0, 1)) {
            static const char message[] = "macos-msync-async-noop: active\n";
            (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        }
        return 0;
    }

    return (int)syscall(SYS_msync, address, length, flags);
}

#define DYLD_INTERPOSE(replacement, replacee)                                                \
    __attribute__((used)) static struct {                                                    \
        const void *replacement;                                                             \
        const void *replacee;                                                                \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {                 \
        (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&replacee    \
    }

DYLD_INTERPOSE(replacement_msync, msync);
