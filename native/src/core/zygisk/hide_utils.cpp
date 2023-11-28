#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <string>
#include <iostream>
#include <set>
#include <list>

#include "elf_util.h"
#include "zygisk.hpp"
#include <consts.hpp>
#include <base.hpp>


class ProtectedDataGuard {

public:
    ProtectedDataGuard() {
        if (ctor != nullptr)
            (this->*ctor)();
    }

    ~ProtectedDataGuard() {
        if (dtor != nullptr)
            (this->*dtor)();
    }

    static bool setup(const SandHook::ElfImg &linker) {
        ctor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                "__dl__ZN18ProtectedDataGuardC2Ev")),
                .adj = 0}}
                .f;
        dtor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                "__dl__ZN18ProtectedDataGuardD2Ev")),
                .adj = 0}}
                .f;
        return ctor != nullptr && dtor != nullptr;
    }

    ProtectedDataGuard(const ProtectedDataGuard &) = delete;

    void operator=(const ProtectedDataGuard &) = delete;

private:
    using FuncType = void (ProtectedDataGuard::*)();

    static FuncType ctor;
    static FuncType dtor;

    union MemFunc {
        FuncType f;

        struct {
            void *p;
            std::ptrdiff_t adj;
        } data;
    };
};

ProtectedDataGuard::FuncType ProtectedDataGuard::ctor = nullptr;
ProtectedDataGuard::FuncType ProtectedDataGuard::dtor = nullptr;

struct soinfo;

soinfo *solist = nullptr;
soinfo **sonext = nullptr;
soinfo *somain = nullptr;

template<typename T>
inline T *getStaticVariable(const SandHook::ElfImg &linker, std::string_view name) {
    auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name.data()));
    return addr == nullptr ? nullptr : *addr;
}

struct soinfo {
    soinfo *next() {
        return *(soinfo **) ((uintptr_t) this + solist_next_offset);
    }

    void next(soinfo *si) {
        *(soinfo **) ((uintptr_t) this + solist_next_offset) = si;
    }

    const char *get_realpath() {
        return get_realpath_sym ? get_realpath_sym(this) : ((std::string *) (
                (uintptr_t) this + solist_realpath_offset))->c_str();

    }

    static bool setup(const SandHook::ElfImg &linker) {
        get_realpath_sym = reinterpret_cast<decltype(get_realpath_sym)>(linker.getSymbAddress(
                "__dl__ZNK6soinfo12get_realpathEv"));
        auto vsdo = getStaticVariable<soinfo>(linker, "__dl__ZL4vdso");
        char sdk_ver_str[92];
        __system_property_get("ro.build.version.sdk", sdk_ver_str);
        for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
            auto *possible_next = *(void **) ((uintptr_t) solist + i * sizeof(void *));
            if (possible_next == somain || (vsdo != nullptr && possible_next == vsdo)) {
                solist_next_offset = i * sizeof(void *);
                return atoi(sdk_ver_str) < 26 || get_realpath_sym != nullptr;
            }
        }
        ZLOGW("failed to search next offset\n");
        // shortcut
        return atoi(sdk_ver_str) < 26 || get_realpath_sym != nullptr;
    }

#ifdef __LP64__
    constexpr static size_t solist_realpath_offset = 0x1a8;
    inline static size_t solist_next_offset = 0x30;
#else
    constexpr static size_t solist_realpath_offset = 0x174;
    inline static size_t solist_next_offset = 0xa4;
#endif

    // since Android 8
    inline static const char *(*get_realpath_sym)(soinfo *);
};

bool solist_remove_soinfo(soinfo *si) {
    soinfo *prev = nullptr, *trav;
    for (trav = solist; trav != nullptr; trav = trav->next()) {
        if (trav == si) {
            break;
        }
        prev = trav;
    }

    if (trav == nullptr) {
        return false;
    }

    // prev will never be null, because the first entry in solist is
    // always the static libdl_info.
    prev->next(si->next());
    if (si == *sonext) {
        *sonext = prev;
    }

    return true;
}

const auto initialized = []() {
    SandHook::ElfImg linker("/linker");
    return ProtectedDataGuard::setup(linker) &&
           (solist = getStaticVariable<soinfo>(linker, "__dl__ZL6solist")) != nullptr &&
           (sonext = linker.getSymbAddress<soinfo**>("__dl__ZL6sonext")) != nullptr &&
           (somain = getStaticVariable<soinfo>(linker, "__dl__ZL6somain")) != nullptr &&
           soinfo::setup(linker);
}();

std::list<soinfo *> linker_get_solist() {
    std::list<soinfo *> linker_solist{};
    for (auto *iter = solist; iter; iter = iter->next()) {
        linker_solist.push_back(iter);
    }
    return linker_solist;
}

void RemoveZygiskPathsFromSolist() {
    if (!initialized) {
        ZLOGW("linker not initialized\n");
        return;
    }
    ProtectedDataGuard g;
    for (const auto &soinfo : linker_get_solist()) {
        const auto &real_path = soinfo->get_realpath();
        if (real_path == nullptr) continue;
        if (std::string(real_path).ends_with("/" ZYGISKLIB)) {
            ZLOGD("remove path from solist: %s\n", real_path);
            solist_remove_soinfo(soinfo);
        }
    }
}

