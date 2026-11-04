#include "system_info.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {

unsigned int SystemInfo::GetOptimalThreadCount() {
    unsigned int threads = std::thread::hardware_concurrency();
    if (threads == 0) {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        threads = sys_info.dwNumberOfProcessors;
    }
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        const unsigned int ram_gb = static_cast<unsigned int>(mem_status.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL));
        if (ram_gb > 0) {
            const unsigned int ram_cap = std::max(1u, ram_gb / 2u);
            if (threads > ram_cap) {
                threads = ram_cap;
            }
        }
    }
    return (threads > 0) ? threads : 4;
}

std::wstring SystemInfo::GetExecutableDirectory() {
    wchar_t buffer[MAX_PATH * 2];
    DWORD len = GetModuleFileNameW(nullptr, buffer, MAX_PATH * 2);
    if (len == 0) return L"";
    return fs::path(buffer).parent_path().wstring();
}

std::wstring SystemInfo::DiscoverRepoRoot() {
    // 1. Check environment variable OPENFRUIT_ROOT
    wchar_t env_buf[MAX_PATH * 2];
    DWORD env_len = GetEnvironmentVariableW(L"OPENFRUIT_ROOT", env_buf, MAX_PATH * 2);
    if (env_len > 0 && env_len < MAX_PATH * 2 && fs::exists(env_buf)) {
        return fs::path(env_buf).wstring();
    }

    // 2. Search upward from executable directory
    fs::path current = GetExecutableDirectory();
    while (!current.empty() && current != current.root_path()) {
        if (fs::exists(current / ".git")) {
            return current.wstring();
        }
        current = current.parent_path();
    }

    // 3. Search upward from current working directory
    current = fs::current_path();
    while (!current.empty() && current != current.root_path()) {
        if (fs::exists(current / ".git")) {
            return current.wstring();
        }
        current = current.parent_path();
    }

    return fs::current_path().wstring();
}

std::wstring SystemInfo::GetSystem32Directory() {
    wchar_t buffer[MAX_PATH];
    UINT len = GetSystemDirectoryW(buffer, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::wstring(buffer);
    }
    // GetSystemDirectoryW does not fail in practice; fall back to %SystemRoot%.
    wchar_t root[MAX_PATH];
    const DWORD root_length = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    return root_length > 0 && root_length < MAX_PATH ? std::wstring(root, root_length) + L"\\System32" : std::wstring{};
}

std::wstring SystemInfo::GetWslExecutable() {
    fs::path wsl = fs::path(GetSystem32Directory()) / "wsl.exe";
    if (fs::exists(wsl)) {
        return wsl.wstring();
    }
    return L"wsl.exe";
}

std::wstring SystemInfo::ExpandEnvironmentStringsCustom(const std::wstring& input) {
    if (input.empty()) return L"";
    DWORD size = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);
    if (size == 0) return input;
    std::vector<wchar_t> buffer(size);
    ExpandEnvironmentStringsW(input.c_str(), buffer.data(), size);
    return std::wstring(buffer.data());
}

} // namespace OpenFruit
