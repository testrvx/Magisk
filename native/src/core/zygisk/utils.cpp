#include <cinttypes>
#include <base.hpp>
#include "zygisk.hpp"
#include <lsplt.hpp>

using namespace std;

static vector<lsplt::MapInfo> find_maps(const char *name) {
    auto maps = lsplt::MapInfo::Scan();
    for (auto iter = maps.begin(); iter != maps.end();) {
        if (iter->path != name) {
            iter = maps.erase(iter);
        } else {
            ++iter;
        }
    }
    return maps;
}

void unmap_all(const char *name) {
    auto maps = find_maps(name);
    for (auto &info : maps) {
        void *addr = reinterpret_cast<void *>(info.start);
        size_t size = info.end - info.start;
        if (info.perms & PROT_READ) {
            // Make sure readable pages are still readable
            void *dummy = xmmap(nullptr, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            mremap(dummy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr);
        } else {
            munmap(addr, size);
        }
    }
}
