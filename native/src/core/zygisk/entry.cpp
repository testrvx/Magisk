#include <libgen.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <android/log.h>
#include <android/dlext.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <base.hpp>
#include <consts.hpp>


#include "ptrace_utils.hpp"
#include "zygisk.hpp"
#include "module.hpp"

using namespace std;

void *self_handle = nullptr;
string native_bridge = "0";
bool stop_trace_zygote = false;
int system_server_fd = -1;

extern "C" [[maybe_unused]] void zygisk_inject_entry(void *handle) {
    self_handle = handle;
    zygisk_logging();
    hook_functions();
    ZLOGD("load success\n");
}

// The following code runs in zygote/app process

static inline bool should_load_modules(uint32_t flags) {
    return (flags & PROCESS_IS_MAGISK_APP) != PROCESS_IS_MAGISK_APP;
}

int remote_get_info(int uid, const char *process, uint32_t *flags, vector<int> &fds) {
    if (int fd = zygisk_request(ZygiskRequest::GET_INFO); fd >= 0) {
        write_int(fd, uid);
        write_string(fd, process);
        xxread(fd, flags, sizeof(*flags));
        if (should_load_modules(*flags)) {
            fds = recv_fds(fd);
        }
        return fd;
    }
    return -1;
}

int remote_request_sulist() {
    if (int fd = zygisk_request(ZygiskRequest::SULIST_ROOT_NS); fd >= 0) {
        int res = read_int(fd);
        close(fd);
        return res;
    }
    return -1;
}

int remote_request_umount() {
    if (int fd = zygisk_request(ZygiskRequest::REVERT_UNMOUNT); fd >= 0) {
        // directly open fd path from magisk proc without recv_fd
        auto ns_path = read_string(fd);
        auto clean_ns = xopen(ns_path.data(), O_RDONLY);
        LOGD("denylist: set to clean ns [%s] fd=[%d]\n", ns_path.data(), clean_ns);
        if (clean_ns > 0) xsetns(clean_ns, CLONE_NEWNS);
        close(clean_ns);
        close(fd);
        return 0;
    }
    return -1;
}

// The following code runs in magiskd

static vector<int> get_module_fds(bool is_64_bit) {
    vector<int> fds;
    // All fds passed to send_fds have to be valid file descriptors.
    // To workaround this issue, send over STDOUT_FILENO as an indicator of an
    // invalid fd as it will always be /dev/null in magiskd
    if (is_64_bit) {
#if defined(__LP64__)
        std::transform(module_list->begin(), module_list->end(), std::back_inserter(fds),
            [](const module_info &info) { return info.z64 < 0 ? STDOUT_FILENO : info.z64; });
#endif
    } else {
        std::transform(module_list->begin(), module_list->end(), std::back_inserter(fds),
            [](const module_info &info) { return info.z32 < 0 ? STDOUT_FILENO : info.z32; });
    }
    return fds;
}

static bool get_exe(int pid, char *buf, size_t sz) {
    char exe[128];
    if (ssprintf(exe, sizeof(exe), "/proc/%d/exe", pid) < 0)
        return false;
    return xreadlink(exe, buf, sz) > 0;
}

static pthread_mutex_t zygiskd_lock = PTHREAD_MUTEX_INITIALIZER;
static int zygiskd_sockets[] = { -1, -1 };
#define zygiskd_socket zygiskd_sockets[is_64_bit]

static void connect_companion(int client, bool is_64_bit) {
    mutex_guard g(zygiskd_lock);

    if (zygiskd_socket >= 0) {
        // Make sure the socket is still valid
        pollfd pfd = { zygiskd_socket, 0, 0 };
        poll(&pfd, 1, 0);
        if (pfd.revents) {
            // Any revent means error
            close(zygiskd_socket);
            zygiskd_socket = -1;
        }
    }
    if (zygiskd_socket < 0) {
        int fds[2];
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
        zygiskd_socket = fds[0];
        if (fork_dont_care() == 0) {
            char exe[64];
            ssprintf(exe, sizeof(exe), "%s/magisk%s", get_magisk_tmp(), (is_64_bit ? "64" : "32"));
            // This fd has to survive exec
            fcntl(fds[1], F_SETFD, 0);
            char buf[16];
            ssprintf(buf, sizeof(buf), "%d", fds[1]);
            execl(exe, "", "zygisk", "companion", buf, (char *) nullptr);
            exit(-1);
        }
        close(fds[1]);
        vector<int> module_fds = get_module_fds(is_64_bit);
        send_fds(zygiskd_socket, module_fds.data(), module_fds.size());
        // Wait for ack
        if (read_int(zygiskd_socket) != 0) {
            LOGE("zygiskd startup error\n");
            return;
        }
    }
    send_fd(zygiskd_socket, client);
}

static int clean_ns64 = -1, clean_ns32 = -1;

#ifndef SYS_mmap
#define SYS_mmap SYS_mmap2
#endif

#define signal (WSTOPSIG(status))

static long xptrace(int request, pid_t pid, void *addr = nullptr, void *data = nullptr) {
    long ret = ptrace(request, pid, addr, data);
    if (ret < 0)
        PLOGE("ptrace %d", pid);
    return ret;
}

static inline long xptrace(int request, pid_t pid, void *addr, uintptr_t data) {
    return xptrace(request, pid, addr, reinterpret_cast<void *>(data));
}

static void ptrace_unload_remap(int remote_pid) {
    int pipe_fd[2];
    pipe(pipe_fd);

    if (fork_dont_care() == 0) {
        // ptrace to replace munmmap with mmap anonymous
        int ptrace_ret = xptrace(PTRACE_SEIZE, remote_pid, 0, PTRACE_O_TRACESYSGOOD);

        write_int(pipe_fd[1], 0);

        if (!ptrace_ret) {
            LOGD("zygisk: attached pid=%d\n", remote_pid);

	    int status;
            struct user_regs_struct regs, backup;
            
            for (int result;;) {
                result = waitpid(remote_pid, &status, __WALL);
                if (result == -1) {
                    if (errno == EINTR) {
                        continue;
                    } else {
                        PLOGE("wait %d", remote_pid);
                        break;
                    }
                }
                if (WIFEXITED(status))
                    break; // process died
                if (signal == (SIGTRAP|0x80)) {
                    // Get the current register values
                    get_regs(remote_pid, regs);
            
                    // Check if the system call is munmap
                    if (regs.REG_SYSNO == SYS_munmap)
                    {
                        // munmap entry
                        LOGD("zygisk: process %d calling munmap(addr=%llx, len=%lld)\n", remote_pid, regs.REG_SYSARG0, regs.REG_SYSARG1);
                        
                        // check if mapping is libzygisk.so
                        bool mapped_libzygisk = false;
                        bool mapping_is_libzygisk = false;
                        for (auto &info : Scan_proc(std::to_string(remote_pid))) {
                            if (strstr(info.path.data(), "/magisk") == nullptr)
                                continue;
                            mapped_libzygisk = true;
	                    if (info.start == regs.REG_SYSARG0) {
	                        mapping_is_libzygisk = true;
                                break;
			    }
                        }
                        if (!mapping_is_libzygisk) {
                            // Continue the remote_pid until munmap exits
                            xptrace(PTRACE_SYSCALL, remote_pid);
                            waitpid(remote_pid, &status, __WALL);
                            goto next_entry;
                        }
                        if (!mapped_libzygisk) {
                            // libzygisk unmapped 
                            break;
                        }
    
                        backup = regs;
    
                        // Replace munmap with mmap system call
                        bool modified_syscall = modify_syscall(remote_pid,
                                       (unsigned long[]){
                                           static_cast<unsigned long>(SYS_mmap),                                // syscall
                                           static_cast<unsigned long>(backup.REG_SYSARG0),                      // addr
                                           static_cast<unsigned long>(backup.REG_SYSARG1),                      // len
                                           static_cast<unsigned long>(PROT_READ),                               // prot
                                           static_cast<unsigned long>(MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED), // flags
                                           static_cast<unsigned long>(-1),                                      // fd
                                           static_cast<unsigned long>(0)                                        // offset
                                       });
                        
                        // Continue the remote_pid until mmap exits
                        xptrace(PTRACE_SYSCALL, remote_pid);
                        waitpid(remote_pid, &status, __WALL);
    
                        if (modified_syscall) {
                            get_regs(remote_pid, regs);
                            LOGD("zygisk: pid=%d, mmap ret=%p\n", remote_pid, regs.REG_RET);
            
                            // redirect return value from mmap to munmap
                            regs.REG_RET = !(regs.REG_RET);
                        
                            LOGD("zygisk: pid=%d, redirect to unmmap ret=%lld\n", remote_pid, regs.REG_RET);
                            set_regs(remote_pid, regs);
			}
                    } else {
                        // Continue the remote_pid until syscall exits
                        xptrace(PTRACE_SYSCALL, remote_pid);
                        waitpid(remote_pid, &status, __WALL);
                    }
                }
                next_entry:
                xptrace(PTRACE_SYSCALL, remote_pid, 0, (WIFSTOPPED(status) && !(signal & SIGTRAP))? signal : 0);
            }
            LOGD("zygisk: cleanup completed pid=%d\n", remote_pid);
            xptrace(PTRACE_DETACH, remote_pid);
        } else {
            LOGD("zygisk: failed to attach pid=%d\n", remote_pid);
        }
        _exit(0);
    } else {
        read_int(pipe_fd[0]);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
    }
}

#undef signal

extern bool uid_granted_root(int uid);
static void get_process_info(int client, const sock_cred *cred) {
    int uid = read_int(client);
    string process = read_string(client);

    uint32_t flags = 0;

    check_pkg_refresh();
    if (is_deny_target(uid, process)) {
        flags |= (sulist_enabled)? PROCESS_ON_ALLOWLIST : PROCESS_ON_DENYLIST;
    }
    int manager_app_id = get_manager();
    if (to_app_id(uid) == manager_app_id) {
        flags |= PROCESS_IS_MAGISK_APP;
    }
    if (denylist_enforced) {
        flags |= MAGISKHIDE_ENABLED;
    }
    if (sulist_enabled){
        flags |= ALLOWLIST_ENFORCING;
        // treat "not on sulist" as "on denylist" for zygisk modules
        if ((flags & PROCESS_ON_ALLOWLIST) != PROCESS_ON_ALLOWLIST)
            flags |= PROCESS_ON_DENYLIST;
    }
    if (uid_granted_root(uid)) {
        flags |= PROCESS_GRANTED_ROOT;
    }
    
    if ((denylist_enforced || sulist_enabled) && (flags & PROCESS_ON_DENYLIST)) {
        ptrace_unload_remap(cred->pid);
	}

    xwrite(client, &flags, sizeof(flags));

    if (should_load_modules(flags)) {
        char buf[256];
        if (!get_exe(cred->pid, buf, sizeof(buf))) {
            LOGW("zygisk: remote process %d probably died, abort\n", cred->pid);
            send_fd(client, -1);
            return;
        }
        vector<int> fds = get_module_fds(str_ends(buf, "64"));
        send_fds(client, fds.data(), fds.size());
    }

    if (uid != 1000 || process != "system_server")
        return;

    if (system_server_fd >= 0) close(system_server_fd);
    system_server_fd = xopen(("/proc/"s + to_string(cred->pid)).data(), O_PATH);

    // Collect module status from system_server
    int slots = read_int(client);
    dynamic_bitset bits;
    for (int i = 0; i < slots; ++i) {
        dynamic_bitset::slot_type l = 0;
        xxread(client, &l, sizeof(l));
        bits.emplace_back(l);
    }
    for (int id = 0; id < module_list->size(); ++id) {
        if (!as_const(bits)[id]) {
            // Either not a zygisk module, or incompatible
            char buf[4096];
            ssprintf(buf, sizeof(buf), MODULEROOT "/%s/zygisk",
                module_list->operator[](id).name.data());
            if (int dirfd = open(buf, O_RDONLY | O_CLOEXEC); dirfd >= 0) {
                close(xopenat(dirfd, "unloaded", O_CREAT | O_RDONLY, 0644));
                close(dirfd);
            }
        }
    }
}

static void mount_magisk_to_remote(int client, const sock_cred *cred) {
    int pid = fork();
    if (pid == 0) {
        do_mount_magisk(cred->pid);
        _exit(0);
    } else if (pid > 0) {
        waitpid(pid, nullptr, 0);
        write_int(client, 0);
    } else {
        write_int(client, -1);
    }
}

static int get_clean_ns(pid_t pid) {
    int pipe_fd[2];
    pipe(pipe_fd);
    int child = xfork();
    if (!child) {
        switch_mnt_ns(pid);
        xunshare(CLONE_NEWNS);
        revert_unmount();
        write_int(pipe_fd[1], 0);
        read_int(pipe_fd[0]);
        exit(0);
    } else {
        read_int(pipe_fd[0]);
        char buf[PATH_MAX];
        ssprintf(buf, PATH_MAX, "/proc/%d/ns/mnt", child);
        auto clean_ns = (child > 0)? open(buf, O_RDONLY) : -1;
        write_int(pipe_fd[1], 0);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        if (child > 0) waitpid(child, nullptr, 0);
        return clean_ns;
    }
}

static void get_moddir(int client) {
    int id = read_int(client);
    char buf[4096];
    ssprintf(buf, sizeof(buf), MODULEROOT "/%s", module_list->operator[](id).name.data());
    int dfd = xopen(buf, O_RDONLY | O_CLOEXEC);
    send_fd(client, dfd);
    close(dfd);
}

void zygisk_handler(int client, const sock_cred *cred) {
    int code = read_int(client);
    char buf[256];
    switch (code) {
    case ZygiskRequest::GET_INFO:
        get_process_info(client, cred);
        break;
    case ZygiskRequest::CONNECT_COMPANION:
        if (get_exe(cred->pid, buf, sizeof(buf))) {
            connect_companion(client, str_ends(buf, "64"));
        } else {
            LOGW("zygisk: remote process %d probably died, abort\n", cred->pid);
        }
        break;
    case ZygiskRequest::GET_MODDIR:
        get_moddir(client);
        break;
    case ZygiskRequest::SULIST_ROOT_NS:
        mount_magisk_to_remote(client, cred);
        break;
    case ZygiskRequest::REVERT_UNMOUNT: {
        get_exe(cred->pid, buf, sizeof(buf));
        int clean_ns = -1;
        if (su_bin_fd >= 0) {
            if (str_ends(buf, "64")) {
                if (clean_ns64 < 0)
                    clean_ns64 = get_clean_ns(cred->pid);
                clean_ns = clean_ns64;
            } else {
                if (clean_ns32 < 0)
                    clean_ns32 = get_clean_ns(cred->pid);
                clean_ns = clean_ns32;
            }
        }
        // send path to zygote instead send_fd
        write_string(client, "/proc/"s + to_string(getpid()) + "/fd/" + to_string(clean_ns));
        break;
    }
    default:
        // Unknown code
        break;
    }
    close(client);
}

void reset_zygisk(bool restore) {
    if (!zygisk_enabled) return;
    static atomic_uint zygote_start_count{1};
    if (!restore) {
        close(zygiskd_sockets[0]);
        close(zygiskd_sockets[1]);
        zygiskd_sockets[0] = zygiskd_sockets[1] = -1;
        close(clean_ns64);
        close(clean_ns32);
        clean_ns64 = clean_ns32 = -1;
    }
    if (restore) {
        zygote_start_count = 1;
        stop_trace_zygote = false;
    } else if (zygote_start_count.fetch_add(1) > 3) {
        LOGW("zygote crashes too many times, stop injecting\n");
        stop_trace_zygote = true;
    }
}
