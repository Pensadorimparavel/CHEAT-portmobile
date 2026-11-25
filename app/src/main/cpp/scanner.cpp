#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <sys/uio.h>

namespace {

struct Region { uint64_t start, end; };

std::vector<uint64_t> g_results;
std::mutex g_mu;
constexpr size_t MAX_RESULTS = 4000000;

// tipos: 0=int32 1=int64 2=float 3=double
int typeSize(int t) { return (t == 1 || t == 3) ? 8 : 4; }

bool parseValue(int t, const char* s, uint8_t* out) {
    char* e = nullptr;
    switch (t) {
        case 0: { long v = strtol(s, &e, 10); if (e == s || *e) return false; int32_t x = (int32_t)v; memcpy(out, &x, 4); return true; }
        case 1: { long long v = strtoll(s, &e, 10); if (e == s || *e) return false; int64_t x = v; memcpy(out, &x, 8); return true; }
        case 2: { float f = strtof(s, &e); if (e == s || *e) return false; memcpy(out, &f, 4); return true; }
        default: { double d = strtod(s, &e); if (e == s || *e) return false; memcpy(out, &d, 8); return true; }
    }
}

std::string formatValue(int t, const uint8_t* b) {
    char buf[64];
    switch (t) {
        case 0: { int32_t x; memcpy(&x, b, 4); snprintf(buf, sizeof buf, "%d", x); break; }
        case 1: { int64_t x; memcpy(&x, b, 8); snprintf(buf, sizeof buf, "%lld", (long long)x); break; }
        case 2: { float f; memcpy(&f, b, 4); snprintf(buf, sizeof buf, "%g", f); break; }
        default: { double d; memcpy(&d, b, 8); snprintf(buf, sizeof buf, "%g", d); break; }
    }
    return buf;
}

int openMem(int pid, int flags) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/mem", pid);
    return open(p, flags | O_CLOEXEC);
}

// Acesso à memória: /proc/<pid>/mem; se falhar no PRÓPRIO processo,
// usa process_vm_readv/writev (o clonador pode bloquear /proc/self/mem).
struct Mem {
    int fd = -1;
    int pid = 0;
    bool vm = false;
    int err = 0;
    bool ok() const { return fd >= 0 || vm; }
};

Mem openMemory(int pid, int flags) {
    Mem m;
    m.pid = pid;
    m.fd = openMem(pid, flags);
    if (m.fd < 0) {
        m.err = errno;
        if (pid == getpid()) m.vm = true;
    }
    return m;
}

void closeMemory(Mem& m) { if (m.fd >= 0) close(m.fd); m.fd = -1; }

ssize_t memRead(const Mem& m, void* buf, size_t n, uint64_t addr) {
    if (m.fd >= 0) return pread64(m.fd, buf, n, (off64_t)addr);
    iovec l{buf, n};
    iovec r{(void*)(uintptr_t)addr, n};
    return process_vm_readv(m.pid, &l, 1, &r, 1, 0);
}

ssize_t memWrite(const Mem& m, const void* buf, size_t n, uint64_t addr) {
    if (m.fd >= 0) return pwrite64(m.fd, buf, n, (off64_t)addr);
    iovec l{(void*)buf, n};
    iovec r{(void*)(uintptr_t)addr, n};
    return process_vm_writev(m.pid, &l, 1, &r, 1, 0);
}

// regioes rw que nao sao arquivo mapeado (heap, anon, etc.)
std::vector<Region> readRegions(int pid) {
    std::vector<Region> out;
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    FILE* f = fopen(p, "r");
    if (!f) return out;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        unsigned long long s, e;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        const char* path = line;
        for (int i = 0; i < 5; i++) {
            while (*path && *path != ' ') path++;
            while (*path == ' ') path++;
        }
        if (*path == '/') continue;                       // arquivo mapeado
        if (strncmp(path, "[vvar", 5) == 0 || strncmp(path, "[vdso", 5) == 0) continue;
        out.push_back({(uint64_t)s, (uint64_t)e});
    }
    fclose(f);
    return out;
}

std::string toStd(JNIEnv* env, jstring js) {
    const char* c = env->GetStringUTFChars(js, nullptr);
    std::string s = c ? c : "";
    if (c) env->ReleaseStringUTFChars(js, c);
    return s;
}

} // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_memscan_app_NativeScanner_probe(JNIEnv* env, jclass, jint pid) {
    std::string out;
    auto regs = readRegions(pid);
    out += "Regioes rw (anon/heap): " + std::to_string(regs.size()) + "\n";
    out += std::string("Processo proprio: ") + (pid == getpid() ? "sim" : "nao") + "\n";
    Mem m = openMemory(pid, O_RDONLY);
    if (m.fd < 0) out += std::string("/proc/mem (leitura): FALHOU - ") + strerror(m.err) + "\n";
    if (m.ok()) {
        int ok = 0, tried = 0;
        uint8_t b[8];
        for (auto& r : regs) {
            if (tried >= 50) break;
            tried++;
            if (memRead(m, b, 8, r.start) == 8) ok++;
        }
        out += std::string("Leitura via ") + (m.fd >= 0 ? "/proc/mem" : "process_vm_readv") +
               ": " + std::to_string(ok) + "/" + std::to_string(tried) + " regioes\n";
        closeMemory(m);
    }
    Mem w = openMemory(pid, O_RDWR);
    if (w.fd >= 0) { out += "Abrir mem (escrita): OK"; closeMemory(w); }
    else out += std::string("Abrir mem (escrita): FALHOU - ") + strerror(w.err) +
                (w.vm ? " (vai usar process_vm_writev)" : "");
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jlong JNICALL
Java_com_memscan_app_NativeScanner_firstScan(JNIEnv* env, jclass, jint pid, jint type, jstring jval) {
    uint8_t target[8];
    if (!parseValue(type, toStd(env, jval).c_str(), target)) return -EINVAL;
    int sz = typeSize(type);
    Mem m = openMemory(pid, O_RDONLY);
    if (!m.ok()) return -m.err;
    auto regs = readRegions(pid);
    if (regs.empty()) { closeMemory(m); return -ENOENT; }

    std::lock_guard<std::mutex> lk(g_mu);
    g_results.clear();
    const size_t CH = 1 << 20;
    std::vector<uint8_t> buf(CH + 8);
    for (auto& r : regs) {
        for (uint64_t addr = r.start; addr < r.end; addr += CH) {
            size_t len = (size_t)std::min<uint64_t>(CH, r.end - addr);
            size_t want = (size_t)std::min<uint64_t>(len + 8, r.end - addr);
            ssize_t n = memRead(m, buf.data(), want, addr);
            if (n < sz) continue;
            size_t limit = std::min<size_t>(len, (size_t)n - sz + 1);
            for (size_t i = 0; i < limit; i += 4) {
                if (memcmp(buf.data() + i, target, sz) == 0) {
                    g_results.push_back(addr + i);
                    if (g_results.size() >= MAX_RESULTS) { closeMemory(m); return (jlong)g_results.size(); }
                }
            }
        }
    }
    closeMemory(m);
    return (jlong)g_results.size();
}

JNIEXPORT jlong JNICALL
Java_com_memscan_app_NativeScanner_nextScan(JNIEnv* env, jclass, jint pid, jint type, jstring jval) {
    uint8_t target[8], cur[8];
    if (!parseValue(type, toStd(env, jval).c_str(), target)) return -EINVAL;
    int sz = typeSize(type);
    Mem m = openMemory(pid, O_RDONLY);
    if (!m.ok()) return -m.err;

    std::lock_guard<std::mutex> lk(g_mu);
    std::vector<uint64_t> keep;
    for (uint64_t a : g_results) {
        if (memRead(m, cur, sz, a) == sz && memcmp(cur, target, sz) == 0) keep.push_back(a);
    }
    g_results.swap(keep);
    closeMemory(m);
    return (jlong)g_results.size();
}

JNIEXPORT jlongArray JNICALL
Java_com_memscan_app_NativeScanner_results(JNIEnv* env, jclass, jint max) {
    std::lock_guard<std::mutex> lk(g_mu);
    jsize n = (jsize)std::min<size_t>((size_t)max, g_results.size());
    jlongArray arr = env->NewLongArray(n);
    std::vector<jlong> tmp(g_results.begin(), g_results.begin() + n);
    env->SetLongArrayRegion(arr, 0, n, tmp.data());
    return arr;
}

JNIEXPORT jstring JNICALL
Java_com_memscan_app_NativeScanner_readValue(JNIEnv* env, jclass, jint pid, jlong addr, jint type) {
    Mem m = openMemory(pid, O_RDONLY);
    if (!m.ok()) return nullptr;
    uint8_t b[8];
    int sz = typeSize(type);
    ssize_t n = memRead(m, b, sz, (uint64_t)addr);
    closeMemory(m);
    if (n != sz) return nullptr;
    return env->NewStringUTF(formatValue(type, b).c_str());
}

JNIEXPORT jlong JNICALL
Java_com_memscan_app_NativeScanner_writeValue(JNIEnv* env, jclass, jint pid, jlong addr, jint type, jstring jval) {
    uint8_t b[8];
    if (!parseValue(type, toStd(env, jval).c_str(), b)) return -EINVAL;
    Mem m = openMemory(pid, O_RDWR);
    if (!m.ok()) return -m.err;
    int sz = typeSize(type);
    ssize_t n = memWrite(m, b, sz, (uint64_t)addr);
    int err = errno;
    closeMemory(m);
    return n == sz ? (jlong)n : (jlong)-err;
}

JNIEXPORT jstring JNICALL
Java_com_memscan_app_NativeScanner_strerror(JNIEnv* env, jclass, jint code) {
    return env->NewStringUTF(strerror(code));
}

} // extern "C"
