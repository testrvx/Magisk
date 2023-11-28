#include <dlfcn.h>
#include <android/dlext.h>
#include <stdio.h>
#include <string>

#if defined(__LP64__)
# define LP_SELECT(lp32, lp64) lp64
#else
# define LP_SELECT(lp32, lp64) lp32
#endif

void remap_all(const char *name);

__attribute__((constructor))
static void zygisk_loader(void) {
    void *handle = dlopen("/system/lib" LP_SELECT("", "64") "/libzygisk.so", RTLD_LAZY);
    remap_all("/system/lib" LP_SELECT("", "64") "/libzygisk.so");
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
	
