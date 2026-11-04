#include "win32_process.hpp"
#include "operation_events.hpp"
#include "process_diagnostics.hpp"

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

namespace OpenFruit {
namespace {

struct ProcessObservation {
    ProcessResult& result;
    OperationSpan span;
    ProcessObservation(ProcessResult& value, const std::wstring& executable,
                       const std::vector<std::wstring>& arguments, const std::wstring& directory)
        : result(value), span("process", CurrentOperationContext()
            ? DescribeCommand(executable, arguments, directory) : JsonValue::ObjectValue()) {}
    ~ProcessObservation() {
        try {
            auto data = JsonValue::ObjectValue();
            data.Set("process_id", JsonValue::Number(std::to_string(result.process_id)));
            data.Set("exit_code", JsonValue::Number(std::to_string(result.exit_code)));
            data.Set("win32_error", JsonValue::Number(std::to_string(result.win32_error)));
            const auto native_code = static_cast<unsigned long>(result.exit_code);
            const bool exception_exit = result.launched && (native_code & 0xf0000000UL) == 0xc0000000UL;
            data.Set("output_truncated", JsonValue::Boolean(result.output_truncated));
            data.Set("callback_failed", JsonValue::Boolean(result.callback_failed));
            data.Set("exit_kind", JsonValue::String(result.callback_failed ? "callback_failed" : result.cancelled ? "cancelled" : result.timed_out ? "deadline" : !result.launched ? "launch_failed" :
                exception_exit ? "native_exception_exit" : result.success ? "success" : "tool_error"));
            if (exception_exit) {
                data.Set("exception_code", JsonValue::Number(std::to_string(native_code)));
                data.Set("stack_trace_status", JsonValue::String(result.tool_stack_frame_count
                    ? "tool_output" : "unavailable"));
                data.Set("stack_frame_count", JsonValue::Number(std::to_string(result.tool_stack_frame_count)));
            }
            span.Complete(std::move(data), result.cancelled ? OperationOutcome::Cancelled :
                result.success ? OperationOutcome::Succeeded : OperationOutcome::Failed);
        } catch (...) {}
    }
};

bool EqualsEnvironmentKey(
    const std::wstring& lhs,
    const std::wstring& rhs
) {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (std::size_t i = 0;
         i < lhs.size();
         ++i) {
        if (std::towlower(lhs[i]) !=
            std::towlower(rhs[i])) {
            return false;
        }
    }

    return true;
}

std::wstring EnvironmentKey(
    const std::wstring& entry
) {
    if (entry.empty()) {
        return L"";
    }

    /*
     * Windows may expose pseudo environment entries such as:
     *   =C:=C:\some\directory
     *
     * For them, the key ends at the second '='.
     */
    const std::size_t search_from =
        entry.front() == L'=' ? 1 : 0;

    const std::size_t separator =
        entry.find(
            L'=',
            search_from
        );

    if (separator == std::wstring::npos) {
        return entry;
    }

    return entry.substr(
        0,
        separator
    );
}

bool IsOverridden(
    const std::wstring& key,
    const std::vector<
        std::pair<std::wstring, std::wstring>
    >& overrides
) {
    for (auto it = overrides.rbegin();
         it != overrides.rend();
         ++it) {
        if (EqualsEnvironmentKey(
                key,
                it->first)) {
            return true;
        }
    }

    return false;
}

bool HasLaterOverride(
    std::size_t index,
    const std::vector<
        std::pair<std::wstring, std::wstring>
    >& overrides
) {
    for (std::size_t i = index + 1;
         i < overrides.size();
         ++i) {
        if (EqualsEnvironmentKey(
                overrides[index].first,
                overrides[i].first)) {
            return true;
        }
    }

    return false;
}

std::vector<wchar_t> BuildEnvironmentBlock(
    const std::vector<
        std::pair<std::wstring, std::wstring>
    >& overrides
) {
    std::vector<std::wstring> entries;

    LPWCH current_environment =
        GetEnvironmentStringsW();

    if (current_environment) {
        LPWCH cursor =
            current_environment;

        while (*cursor) {
            const std::wstring entry(cursor);
            const std::wstring key =
                EnvironmentKey(entry);

            /*
             * True override semantics: remove the inherited occurrence before
             * adding the replacement. The previous implementation appended a
             * second PATH entry, leaving DLL resolution dependent on which
             * duplicate Windows selected.
             */
            if (!IsOverridden(
                    key,
                    overrides)) {
                entries.push_back(entry);
            }

            cursor +=
                entry.size() + 1;
        }

        FreeEnvironmentStringsW(
            current_environment
        );
    }

    for (std::size_t i = 0;
         i < overrides.size();
         ++i) {

        /*
         * Last override wins when the caller supplies a duplicate key.
         */
        if (HasLaterOverride(
                i,
                overrides)) {
            continue;
        }

        entries.push_back(
            overrides[i].first +
            L"=" +
            overrides[i].second
        );
    }

    /*
     * Windows documents environment blocks as sorted case-insensitively.
     * Sorting also keeps process creation deterministic.
     */
    std::sort(
        entries.begin(),
        entries.end(),
        [](const std::wstring& lhs,
           const std::wstring& rhs) {
            const std::size_t count =
                lhs.size() < rhs.size()
                    ? lhs.size()
                    : rhs.size();

            for (std::size_t i = 0;
                 i < count;
                 ++i) {
                const wchar_t l =
                    std::towlower(lhs[i]);

                const wchar_t r =
                    std::towlower(rhs[i]);

                if (l < r) {
                    return true;
                }

                if (l > r) {
                    return false;
                }
            }

            return lhs.size() <
                   rhs.size();
        }
    );

    std::vector<wchar_t> block;

    for (const auto& entry :
         entries) {
        block.insert(
            block.end(),
            entry.begin(),
            entry.end()
        );

        block.push_back(L'\0');
    }

    /*
     * Environment blocks terminate with an additional NUL.
     */
    block.push_back(L'\0');

    return block;
}

struct ChildJob {
    HANDLE handle = CreateJobObjectW(nullptr, nullptr);
    DWORD error = handle ? ERROR_SUCCESS : GetLastError();
    ChildJob() {
        if (!handle) return;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        // Breakaway stays opt-in per process: only children created with
        // CREATE_BREAKAWAY_FROM_JOB (shared services that must outlive one
        // command, such as the macro broker) leave the job.
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            error = GetLastError(); CloseHandle(handle); handle = nullptr;
        }
    }
    ~ChildJob() { if (handle) CloseHandle(handle); }
};

} // namespace

std::filesystem::path Win32Process::EventContextRecord(unsigned long process_id, std::uint64_t creation_time) {
    wchar_t temp[MAX_PATH + 1] = {};
    const auto length = GetTempPathW(MAX_PATH + 1, temp);
    const std::filesystem::path base = length && length <= MAX_PATH ? std::filesystem::path(temp) : std::filesystem::temp_directory_path();
    return base / L"OPENFRUIT-event-context" /
           (std::to_wstring(process_id) + L"-" + std::to_wstring(creation_time) + L".ctx");
}

std::wstring Win32Process::ToWide(
    const std::string& str
) {
    if (str.empty()) {
        return L"";
    }

    const int size =
        MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            nullptr,
            0
        );

    std::wstring result(
        size,
        L'\0'
    );

    MultiByteToWideChar(
        CP_UTF8,
        0,
        str.data(),
        static_cast<int>(str.size()),
        result.data(),
        size
    );

    return result;
}

std::string Win32Process::ToNarrow(
    const std::wstring& wstr
) {
    if (wstr.empty()) {
        return "";
    }

    const int size =
        WideCharToMultiByte(
            CP_UTF8,
            0,
            wstr.data(),
            static_cast<int>(wstr.size()),
            nullptr,
            0,
            nullptr,
            nullptr
        );

    std::string result(
        size,
        '\0'
    );

    WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        result.data(),
        size,
        nullptr,
        nullptr
    );

    return result;
}

std::wstring Win32Process::QuoteArgument(
    const std::wstring& arg
) {
    if (arg.empty()) {
        return L"\"\"";
    }

    bool needs_quotes = false;

    for (const wchar_t c : arg) {
        if (c == L' ' ||
            c == L'\t' ||
            c == L'\n' ||
            c == L'\v' ||
            c == L'\"') {
            needs_quotes = true;
            break;
        }
    }

    if (!needs_quotes) {
        return arg;
    }

    std::wstring quoted = L"\"";
    int backslashes = 0;

    for (const wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'\"') {
            quoted.append(
                backslashes * 2 + 1,
                L'\\'
            );

            quoted.push_back(L'\"');
            backslashes = 0;
        } else {
            quoted.append(
                backslashes,
                L'\\'
            );

            backslashes = 0;
            quoted.push_back(c);
        }
    }

    quoted.append(
        backslashes * 2,
        L'\\'
    );

    quoted.push_back(L'\"');
    return quoted;
}

std::wstring Win32Process::BuildCommandLine(
    const std::vector<std::wstring>& args
) {
    std::wstring command_line;

    for (std::size_t i = 0;
         i < args.size();
         ++i) {
        if (i > 0) {
            command_line.push_back(L' ');
        }

        command_line.append(
            QuoteArgument(args[i])
        );
    }

    return command_line;
}

ProcessResult Win32Process::Run(
    const std::wstring& executable,
    const std::vector<std::wstring>& args,
    const std::wstring& working_directory,
    const std::vector<
        std::pair<std::wstring, std::wstring>
    >& env_vars,
    std::function<void(const std::string&)> on_stdout,
    std::function<void(const std::string&)> on_stderr,
    const ProcessRunOptions& options
) {
    ProcessResult result;
    ProcessObservation observation(result, executable, args, working_directory);
    const auto event_context = observation.span.Context();
    const auto sensitive_values = event_context ? SensitiveCommandValues(args) : std::vector<std::string>{};
    const auto cancelled = [&]() { return (options.cancellation && options.cancellation->load()) ||
        (event_context && event_context->CancellationRequested()); };
    const auto deadline = event_context && event_context->control
        ? std::min(options.deadline, event_context->control->deadline) : options.deadline;
    if (cancelled()) { result.cancelled = true; return result; }
    if (std::chrono::steady_clock::now() >= deadline) { result.timed_out = true; return result; }
    ChildJob job;
    if (!job.handle) {
        result.win32_error = job.error;
        result.std_err = "Win32: unable to configure child process ownership.";
        return result;
    }

    SECURITY_ATTRIBUTES security_attributes = {};
    security_attributes.nLength =
        sizeof(SECURITY_ATTRIBUTES);

    security_attributes.bInheritHandle =
        TRUE;

    security_attributes.lpSecurityDescriptor =
        nullptr;

    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HANDLE stderr_read = nullptr;
    HANDLE stderr_write = nullptr;

    if (!CreatePipe(
            &stdout_read,
            &stdout_write,
            &security_attributes,
            0)) {
        result.win32_error = GetLastError();
        result.std_err =
            "Win32: Failed to create stdout pipe.";
        return result;
    }

    SetHandleInformation(
        stdout_read,
        HANDLE_FLAG_INHERIT,
        0
    );

    if (!CreatePipe(
            &stderr_read,
            &stderr_write,
            &security_attributes,
            0)) {
        result.win32_error = GetLastError();
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);

        result.std_err =
            "Win32: Failed to create stderr pipe.";
        return result;
    }

    SetHandleInformation(
        stderr_read,
        HANDLE_FLAG_INHERIT,
        0
    );

    HANDLE stdin_nul =
        CreateFileW(
            L"NUL",
            GENERIC_READ,
            FILE_SHARE_READ |
                FILE_SHARE_WRITE,
            &security_attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

    STARTUPINFOEXW startup_extended{};
    auto& startup_info = startup_extended.StartupInfo;
    startup_info.cb =
        sizeof(STARTUPINFOEXW);

    startup_info.dwFlags =
        STARTF_USESTDHANDLES;

    startup_info.hStdOutput =
        stdout_write;

    startup_info.hStdError =
        stderr_write;

    startup_info.hStdInput =
        stdin_nul != INVALID_HANDLE_VALUE
            ? stdin_nul
            : GetStdHandle(
                  STD_INPUT_HANDLE
              );

    PROCESS_INFORMATION process_info = {};

    std::wstring command_line =
        BuildCommandLine(args);

    std::vector<wchar_t> command_buffer(
        command_line.begin(),
        command_line.end()
    );

    command_buffer.push_back(L'\0');

    LPCWSTR executable_pointer =
        nullptr;

    if (!executable.empty() &&
        (executable.find(L'\\') !=
             std::wstring::npos ||
         executable.find(L'/') !=
             std::wstring::npos)) {
        executable_pointer =
            executable.c_str();
    }

    LPCWSTR directory_pointer =
        working_directory.empty()
            ? nullptr
            : working_directory.c_str();

    std::vector<wchar_t> environment_block;
    LPVOID environment_pointer = nullptr;

    // Per-span identifiers stay out of the child's environment: tools such as
    // SwiftPM key their caches by environment, so a fresh span or build ID per
    // invocation would invalidate them. The context is published per process.
    const auto& child_environment = env_vars;
    if (!child_environment.empty()) {
        environment_block =
            BuildEnvironmentBlock(
                child_environment
            );

        environment_pointer =
            environment_block.data();
    }

    SIZE_T attribute_bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_bytes);
    std::vector<unsigned char> attribute_storage(attribute_bytes);
    startup_extended.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
    const bool attributes_initialized = InitializeProcThreadAttributeList(startup_extended.lpAttributeList, 1, 0, &attribute_bytes) != FALSE;
    HANDLE inherited[] = {stdout_write, stderr_write, stdin_nul};
    const bool attributes_ready = attributes_initialized && stdin_nul != INVALID_HANDLE_VALUE &&
        UpdateProcThreadAttribute(startup_extended.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  inherited, sizeof(inherited), nullptr, nullptr);
    if (!attributes_ready) {
        result.win32_error = GetLastError();
        if (attributes_initialized) DeleteProcThreadAttributeList(startup_extended.lpAttributeList);
        CloseHandle(stdout_read); CloseHandle(stdout_write); CloseHandle(stderr_read); CloseHandle(stderr_write);
        if (stdin_nul != INVALID_HANDLE_VALUE) CloseHandle(stdin_nul);
        result.std_err = "Win32: unable to restrict inherited handles.";
        return result;
    }
    const BOOL created =
        CreateProcessW(
            executable_pointer,
            command_buffer.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            environment_pointer,
            directory_pointer,
            &startup_info,
            &process_info
        );

    const DWORD creation_error = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(startup_extended.lpAttributeList);

    CloseHandle(stdout_write);
    CloseHandle(stderr_write);

    if (stdin_nul !=
        INVALID_HANDLE_VALUE) {
        CloseHandle(stdin_nul);
    }

    if (!created) {
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);

        const DWORD error = creation_error;
        result.win32_error = error;

        result.std_err =
            "Win32: CreateProcessW failed with error code: " +
            std::to_string(error);

        return result;
    }

    std::filesystem::path context_record;
    if (event_context) {
        FILETIME created{}, ended{}, kernel{}, user{};
        if (GetProcessTimes(process_info.hProcess, &created, &ended, &kernel, &user)) {
            context_record = EventContextRecord(process_info.dwProcessId,
                (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime);
            std::error_code ignored;
            std::filesystem::create_directories(context_record.parent_path(), ignored);
            std::ofstream record(context_record, std::ios::binary | std::ios::trunc);
            record << ToNarrow(event_context->journal_directory.wstring()) << '\n'
                   << event_context->build_id << '\n' << event_context->span_id << '\n';
            if (!record) context_record.clear();
        }
    }
    struct RecordCleanup {
        const std::filesystem::path& path;
        ~RecordCleanup() { if (!path.empty()) { std::error_code ignored; std::filesystem::remove(path, ignored); } }
    } record_cleanup{context_record};
    if (!AssignProcessToJobObject(job.handle, process_info.hProcess) || ResumeThread(process_info.hThread) == static_cast<DWORD>(-1)) {
        result.win32_error = GetLastError();
        TerminateProcess(process_info.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process_info.hProcess, INFINITE);
        CloseHandle(process_info.hProcess); CloseHandle(process_info.hThread);
        CloseHandle(stdout_read); CloseHandle(stderr_read);
        result.std_err = "Win32: child could not be assigned/resumed under process ownership.";
        return result;
    }
    result.launched = true;
    result.process_id = process_info.dwProcessId;
    if (event_context) {
        auto data = JsonValue::ObjectValue();
        data.Set("process_id", JsonValue::Number(std::to_string(result.process_id)));
        event_context->Emit("process.started", std::move(data));
    }

    std::atomic<std::size_t> observed_stack_frames{0};
    std::atomic<bool> capture_truncated{false};
    std::atomic<bool> callback_failed{false};
    std::thread stdout_thread(
        [stdout_read,
         &result,
         on_stdout, event_context, working_directory, sensitive_values, &observed_stack_frames, &options, &capture_truncated, &callback_failed]() {
            ProcessDiagnostics diagnostics(event_context, working_directory, sensitive_values);
            char buffer[4096];
            DWORD bytes_read = 0;

            while (ReadFile(
                       stdout_read,
                       buffer,
                       sizeof(buffer),
                       &bytes_read,
                       nullptr) &&
                   bytes_read > 0) {
                const std::string chunk(
                    buffer,
                    bytes_read
                );

                const auto available = options.capture_limit_bytes - std::min(options.capture_limit_bytes, result.std_out.size());
                result.std_out.append(chunk, 0, std::min(available, chunk.size()));
                if (available < chunk.size()) capture_truncated = true;
                try { diagnostics.Feed(chunk); } catch (...) {}

                if (on_stdout) {
                    try { on_stdout(chunk); } catch (...) { callback_failed = true; }
                }
            }

            try { diagnostics.Finish(); } catch (...) {}
            observed_stack_frames.fetch_add(diagnostics.StackFrameCount());

            CloseHandle(stdout_read);
        }
    );

    std::thread stderr_thread(
        [stderr_read,
         &result,
         on_stderr, event_context, working_directory, sensitive_values, &observed_stack_frames, &options, &capture_truncated, &callback_failed]() {
            ProcessDiagnostics diagnostics(event_context, working_directory, sensitive_values);
            char buffer[4096];
            DWORD bytes_read = 0;

            while (ReadFile(
                       stderr_read,
                       buffer,
                       sizeof(buffer),
                       &bytes_read,
                       nullptr) &&
                   bytes_read > 0) {
                const std::string chunk(
                    buffer,
                    bytes_read
                );

                const auto available = options.capture_limit_bytes - std::min(options.capture_limit_bytes, result.std_err.size());
                result.std_err.append(chunk, 0, std::min(available, chunk.size()));
                if (available < chunk.size()) capture_truncated = true;
                try { diagnostics.Feed(chunk); } catch (...) {}

                if (on_stderr) {
                    try { on_stderr(chunk); } catch (...) { callback_failed = true; }
                }
            }

            try { diagnostics.Finish(); } catch (...) {}
            observed_stack_frames.fetch_add(diagnostics.StackFrameCount());

            CloseHandle(stderr_read);
        }
    );

    for (;;) {
        const DWORD wait = WaitForSingleObject(process_info.hProcess, 50);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) result.win32_error = GetLastError();
        result.cancelled = cancelled();
        result.timed_out = std::chrono::steady_clock::now() >= deadline;
        if (wait == WAIT_FAILED || result.cancelled || result.timed_out || callback_failed.load()) {
            if (!TerminateJobObject(job.handle, ERROR_PROCESS_ABORTED)) result.win32_error = GetLastError();
            // Closing the job is the kernel-backed fallback if explicit
            // termination fails, and also prevents descendants retaining pipes.
            CloseHandle(job.handle); job.handle = nullptr;
            WaitForSingleObject(process_info.hProcess, INFINITE);
            break;
        }
    }

    DWORD exit_code = 0;

    if (!GetExitCodeProcess(
        process_info.hProcess,
        &exit_code
    )) result.win32_error = GetLastError();

    result.exit_code =
        static_cast<int>(
            exit_code
        );

    result.success = exit_code == 0 && !result.cancelled && !result.timed_out && !result.win32_error;

    CloseHandle(
        process_info.hProcess
    );

    CloseHandle(
        process_info.hThread
    );

    // A command's descendants cannot outlive its invocation, even when its
    // main process exits successfully and leaves inherited pipes open.
    if (job.handle) { CloseHandle(job.handle); job.handle = nullptr; }
    stdout_thread.join();
    stderr_thread.join();
    result.tool_stack_frame_count = observed_stack_frames.load();
    result.output_truncated = capture_truncated.load();
    result.callback_failed = callback_failed.load();
    if (result.output_truncated || result.callback_failed) result.success = false;

    return result;
}

} // namespace OpenFruit
