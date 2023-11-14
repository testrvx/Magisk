#include <dlfcn.h>
#include <android/dlext.h>
#include <stdio.h>
#include <string.h>

#if defined(__LP64__)
# define LP_SELECT(lp32, lp64) lp64
#else
# define LP_SELECT(lp32, lp64) lp32
#endif

__attribute__((constructor))
static void zygisk_loader(void) {
#define ZYGISK_PATH "/system/lib" LP_SELECT("", "64") "/libzygisk.so"
    void *handle = dlopen(ZYGISK_PATH, RTLD_LAZY);
    if (handle) {
        if (auto fp = fopen("/proc/self/attr/current", "r")) {
            char buf[1024];
            fscanf(fp, "%s", buf);
            fclose(fp);
            if (strcmp(buf, "u:r:zygote:s0") == 0) {
                void(*entry)(void*) = dlsym(handle, "zygisk_inject_entry");
                if (entry) {
                    entry(handle);
                }
            }
        }
        void (*unload)(void) = dlsym(handle, "unload_loader");
        if (unload) {
            __attribute__((musttail)) return unload();
        }
    }
}
	
