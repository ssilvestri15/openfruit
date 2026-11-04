#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <functional>
#include <atomic>
#include <chrono>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace OpenFruit {

struct ProcessResult {
    int exit_code = -1;
    std::string std_out;
    std::string std_err;
    bool success = false;
    unsigned long process_id = 0;
    unsigned long win32_error = 0;
    bool launched = false;
    std::size_t tool_stack_frame_count = 0;
    bool cancelled = false;
    bool timed_out = false;
    bool output_truncated = false;
    bool callback_failed = false;
};

struct ProcessRunOptions {
    std::shared_ptr<std::atomic<bool>> cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::size_t capture_limit_bytes = 16 * 1024 * 1024;
};

class Win32Process {
public:
    static std::wstring ToWide(const std::string& str);
    static std::string ToNarrow(const std::wstring& wstr);
    static std::wstring QuoteArgument(const std::wstring& arg);
    static std::wstring BuildCommandLine(const std::vector<std::wstring>& args);
    // Event context of a process started by Run, keyed by its PID and creation
    // time. Descendants find it through their ancestry; it is never placed in
    // the environment, which build tools hash into their caches.
    static std::filesystem::path EventContextRecord(unsigned long process_id, std::uint64_t creation_time);

    static ProcessResult Run(
        const std::wstring& executable,
        const std::vector<std::wstring>& args,
        const std::wstring& working_directory = L"",
        const std::vector<std::pair<std::wstring, std::wstring>>& env_vars = {},
        std::function<void(const std::string&)> on_stdout = nullptr,
        std::function<void(const std::string&)> on_stderr = nullptr,
        const ProcessRunOptions& options = {}
    );
};

} // namespace OpenFruit
