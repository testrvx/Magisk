#include <dlfcn.h>
#include <android/dlext.h>
#include <stdio.h>
#include <string>

#if defined(__LP64__)
# define LP_SELECT(lp32, lp64) lp64
#else
# define LP_SELECT(lp32, lp64) lp32
#endif

#define RANDOM_SOCKET_NAME  "d30138f2310a9fb9c54a3e0c21f58591\0"

void remap_all(const char *name);

__attribute__((constructor))
static void zygisk_loader(void) {
    char ZYGISK_PATH[1024];
    sprintf(ZYGISK_PATH, "/dev/%s.libzygisk.so." LP_SELECT("32", "64"), RANDOM_SOCKET_NAME);

    void *handle = dlopen(ZYGISK_PATH, RTLD_LAZY);
    remap_all(ZYGISK_PATH);
    if (handle) {
        if (auto fp = fopen("/proc/self/attr/current", "r")) {
            char buf[1024];
            fscanf(fp, "%s", buf);
            fclose(fp);
            if (strcmp(buf, "u:r:zygote:s0") == 0) {
                void(*entry)(void*) = (void (*)(void *))dlsym(handle, "zygisk_inject_entry");
                if (entry) {
                    entry(handle);
                }
            }
        }
        void (*unload)(void) = (void (*)(void))dlsym(handle, "unload_loader");
        if (unload) {
            __attribute__((musttail)) return unload();
        }
    }
}
	
