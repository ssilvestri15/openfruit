#pragma once
#include "transport.hpp"
#include <windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

// A broker owns a pool of long-lived original-provider worker processes, each
// running one unchanged original plugin server that stays bootstrapped across
// compiler sessions. Compiler-facing hosts become clients that relay frames.
// Every request goes to an idle worker after replaying the client's own
// capability and library-load requests that worker has not yet seen, so each
// expansion executes in the same plugin state as a dedicated server.
namespace OpenFruit::MacroHost {

inline constexpr wchar_t RoleEnvironment[] = L"OPENFRUIT_MACRO_HOST_ROLE";
inline constexpr wchar_t BrokerPipeEnvironment[] = L"OPENFRUIT_MACRO_BROKER_PIPE";
inline constexpr wchar_t BrokerScopeEnvironment[] = L"OPENFRUIT_MACRO_BROKER_SCOPE";
inline constexpr wchar_t PoolSizeEnvironment[] = L"OPENFRUIT_MACRO_POOL_SIZE";

inline std::string FirstCommand(const std::string& message) {
    const auto quote = message.find('"');
    const auto end = quote == std::string::npos ? quote : message.find('"', quote + 1);
    return end == std::string::npos ? std::string{} : message.substr(quote + 1, end - quote - 1);
}

// Starts this executable with the given role. The worker receives only its own
// pipe ends; other handles of this process are never inherited.
// Worker stderr (original runtime stop diagnostics) is appended to `error_log`
// when given; otherwise it is discarded.
inline bool SpawnRole(const wchar_t* role, HANDLE child_input, HANDLE child_output, PROCESS_INFORMATION& process,
                      const std::wstring& error_log = {}) {
    wchar_t module[MAX_PATH * 4] = {};
    const auto length = GetModuleFileNameW(nullptr, module, static_cast<DWORD>(std::size(module)));
    if (!length || length >= std::size(module)) return false;
    std::wstring command = L"\"" + std::wstring(module, length) + L"\"";
    std::vector<wchar_t> command_line(command.begin(), command.end()); command_line.push_back(L'\0');
    if (!SetEnvironmentVariableW(RoleEnvironment, role)) return false;
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    HANDLE null_error = INVALID_HANDLE_VALUE;
    std::vector<HANDLE> inherited;
    SIZE_T attribute_size = 0;
    std::vector<unsigned char> attributes;
    BOOL created = FALSE;
    if (child_input && child_output) {
        SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
        if (!error_log.empty())
            null_error = CreateFileW(error_log.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                                     OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (null_error == INVALID_HANDLE_VALUE)
            null_error = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
        if (null_error == INVALID_HANDLE_VALUE) return false;
        inherited = {child_input, child_output, null_error};
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
        attributes.resize(attribute_size);
        auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        if (!InitializeProcThreadAttributeList(list, 1, 0, &attribute_size) ||
            !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
                                       inherited.size() * sizeof(HANDLE), nullptr, nullptr)) {
            CloseHandle(null_error); return false;
        }
        startup.lpAttributeList = list;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_input;
        startup.StartupInfo.hStdOutput = child_output;
        startup.StartupInfo.hStdError = null_error;
        created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
                                 &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(list);
        CloseHandle(null_error);
    } else {
        // A broker serves every host of its configuration, so it must not die
        // with the compile job of the host that happened to start it.
        const DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS;
        created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                                 flags | CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &startup.StartupInfo, &process);
        if (!created && GetLastError() == ERROR_ACCESS_DENIED)
            created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                                     flags, nullptr, nullptr, &startup.StartupInfo, &process);
    }
    SetEnvironmentVariableW(RoleEnvironment, nullptr);
    return created != FALSE;
}

struct BrokerStatistics {
    std::size_t clients = 0, requests = 0, replays = 0, worker_starts = 0, worker_failures = 0;
    std::size_t cache_hits = 0, cache_stores = 0;
};

class Broker {
public:
    explicit Broker(std::size_t pool_size) : pool_size_(std::max<std::size_t>(1, pool_size)) {}
    ~Broker() { for (auto& worker : workers_) Close(*worker); }

    // Serves clients on the named pipe until no client has been connected for
    // `idle`. Returns false when another broker already owns the pipe name.
    bool Serve(const std::wstring& pipe_name, std::chrono::milliseconds idle) {
        HANDLE first = CreatePipeInstance(pipe_name, true);
        if (first == INVALID_HANDLE_VALUE) return false;
        for (std::size_t index = 0; index < pool_size_; ++index) StartWorker();
        std::thread([this, idle] { Watch(idle); }).detach();
        HANDLE pending = first;
        for (;;) {
            const bool connected = ConnectNamedPipe(pending, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
            HANDLE next = CreatePipeInstance(pipe_name, false);
            if (connected) {
                { std::lock_guard lock(mutex_); ++active_clients_; ++statistics_.clients; last_activity_ = Now(); }
                std::thread([this, pending] { ServeClient(pending); }).detach();
            } else {
                CloseHandle(pending);
            }
            if (next == INVALID_HANDLE_VALUE) return true;
            pending = next;
        }
    }
    BrokerStatistics Statistics() { std::lock_guard lock(mutex_); return statistics_; }
    std::function<void(const BrokerStatistics&)> on_exit;
    // Reported when a worker fails a request: the command, the exchange step
    // and the worker's exit code (STILL_ACTIVE when it had not exited).
    std::function<void(const std::string& command, const std::string& step, DWORD exit_code)> on_worker_failure;
    std::wstring worker_error_log;
    // Expansion cache: a key for an expansion request in the client's plugin
    // state (empty when not cacheable), and load/store of the original
    // server's exact response frame for that key.
    std::function<std::string(const std::string& capability, const std::vector<std::string>& loads,
                              const std::string& request)> expansion_key;
    std::function<std::optional<std::string>(const std::string& key)> expansion_load;
    std::function<void(const std::string& key, const std::string& response)> expansion_store;

private:
    struct Worker {
        HANDLE process = nullptr, input = nullptr, output = nullptr;
        bool alive = false, busy = false;
        std::string capability;
        std::set<std::string> loads;
    };
    static std::chrono::steady_clock::time_point Now() { return std::chrono::steady_clock::now(); }
    static HANDLE CreatePipeInstance(const std::wstring& name, bool first) {
        return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                PIPE_UNLIMITED_INSTANCES, 1 << 16, 1 << 16, 0, nullptr);
    }
    static void Close(Worker& worker) {
        if (worker.input) CloseHandle(worker.input);
        if (worker.output) CloseHandle(worker.output);
        if (worker.process) CloseHandle(worker.process);
        worker.input = worker.output = worker.process = nullptr; worker.alive = false;
    }
    void StartWorker() {
        auto worker = std::make_unique<Worker>();
        SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
        HANDLE child_input = nullptr, child_output = nullptr;
        if (!CreatePipe(&child_input, &worker->input, &inherit, 1 << 16) ||
            !CreatePipe(&worker->output, &child_output, &inherit, 1 << 16)) {
            if (child_input) CloseHandle(child_input);
            if (child_output) CloseHandle(child_output);
            Close(*worker); return;
        }
        SetHandleInformation(worker->input, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(worker->output, HANDLE_FLAG_INHERIT, 0);
        PROCESS_INFORMATION process{};
        bool started;
        { std::lock_guard spawn(spawn_mutex_); started = SpawnRole(L"worker", child_input, child_output, process, worker_error_log); }
        CloseHandle(child_input); CloseHandle(child_output);
        if (!started) { Close(*worker); return; }
        CloseHandle(process.hThread);
        worker->process = process.hProcess; worker->alive = true;
        std::lock_guard lock(mutex_);
        ++statistics_.worker_starts;
        workers_.push_back(std::move(worker));
        changed_.notify_all();
    }
    Worker* Acquire() {
        std::unique_lock lock(mutex_);
        for (;;) {
            for (auto& worker : workers_) if (worker->alive && !worker->busy) { worker->busy = true; return worker.get(); }
            if (std::none_of(workers_.begin(), workers_.end(), [](const auto& worker) { return worker->alive; }) &&
                statistics_.worker_failures >= pool_size_ * 4) return nullptr;
            changed_.wait(lock);
        }
    }
    void Release(Worker* worker, bool healthy, const std::string& command = {}, const std::string& step = {}) {
        bool replace = false;
        if (!healthy && on_worker_failure) {
            DWORD exit_code = STILL_ACTIVE;
            if (worker->process && WaitForSingleObject(worker->process, 2000) == WAIT_OBJECT_0)
                GetExitCodeProcess(worker->process, &exit_code);
            on_worker_failure(command, step, exit_code);
        }
        {
            std::lock_guard lock(mutex_);
            worker->busy = false;
            if (!healthy) {
                if (worker->process) TerminateProcess(worker->process, 3);
                Close(*worker); ++statistics_.worker_failures; replace = true;
            }
            changed_.notify_all();
        }
        if (replace) StartWorker();
    }
    static bool Exchange(Worker& worker, const std::string& request, std::string& response) {
        return WriteFrame(worker.input, request) && ReadFrame(worker.output, response) == FrameStatus::Ok;
    }
    void ServeClient(HANDLE client) {
        std::string capability;
        std::vector<std::string> loads;
        for (;;) {
            std::string message, response;
            if (ReadFrame(client, message) != FrameStatus::Ok) break;
            const auto command = FirstCommand(message);
            // Macro expansions are pure functions of the request and the
            // server's plugin state; an identical earlier expansion's response
            // from the original server is returned unchanged.
            std::string key;
            if ((command == "expandAttachedMacro" || command == "expandFreestandingMacro") && expansion_key)
                key = expansion_key(capability, loads, message);
            if (!key.empty() && expansion_load) {
                if (auto cached = expansion_load(key)) {
                    { std::lock_guard lock(mutex_); ++statistics_.requests; ++statistics_.cache_hits; last_activity_ = Now(); }
                    if (!WriteFrame(client, *cached)) break;
                    continue;
                }
            }
            auto* worker = Acquire();
            if (!worker) break;
            bool healthy = true;
            std::size_t replays = 0;
            std::string ignored, step = "request";
            if (command != "getCapability" && !capability.empty() && worker->capability != capability) {
                healthy = Exchange(*worker, capability, ignored); worker->capability = capability; ++replays;
                if (!healthy) step = "replay_capability";
            }
            for (const auto& load : loads) {
                if (!healthy || worker->loads.contains(load)) continue;
                healthy = Exchange(*worker, load, ignored); worker->loads.insert(load); ++replays;
                if (!healthy) step = "replay_load";
            }
            healthy = healthy && Exchange(*worker, message, response);
            if (healthy && command == "getCapability") { capability = message; worker->capability = message; }
            if (healthy && command == "loadPluginLibrary") { loads.push_back(message); worker->loads.insert(message); }
            Release(worker, healthy, command, step);
            { std::lock_guard lock(mutex_); ++statistics_.requests; statistics_.replays += replays; last_activity_ = Now(); }
            if (healthy && !key.empty() && expansion_store && FirstCommand(response) == "expandMacroResult") {
                expansion_store(key, response);
                std::lock_guard lock(mutex_); ++statistics_.cache_stores;
            }
            if (!healthy || !WriteFrame(client, response)) break;
        }
        DisconnectNamedPipe(client); CloseHandle(client);
        std::lock_guard lock(mutex_); --active_clients_; last_activity_ = Now();
    }
    void Watch(std::chrono::milliseconds idle) {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            BrokerStatistics snapshot;
            {
                std::lock_guard lock(mutex_);
                if (active_clients_ || Now() - last_activity_ < idle) continue;
                snapshot = statistics_;
            }
            if (on_exit) on_exit(snapshot);
            // Closing the worker pipes ends each original server with EOF.
            ExitProcess(0);
        }
    }

    const std::size_t pool_size_;
    std::mutex mutex_, spawn_mutex_;
    std::condition_variable changed_;
    std::vector<std::unique_ptr<Worker>> workers_;
    std::size_t active_clients_ = 0;
    std::chrono::steady_clock::time_point last_activity_ = Now();
    BrokerStatistics statistics_;
};

enum class ClientStatus { Served, Unavailable, Failed };
struct ClientReport { std::string step, last_command; DWORD error = 0; std::size_t frames = 0; };

// Relays this host's compiler stream to the broker for `pipe_name`, starting
// the broker when none is listening. Unavailable means nothing was consumed
// from the compiler, so the caller may serve the session directly instead.
inline ClientStatus RunClient(const std::wstring& pipe_name, std::chrono::milliseconds connect_timeout,
                              ClientReport& report) {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    bool spawned = false;
    const auto deadline = std::chrono::steady_clock::now() + connect_timeout;
    while (pipe == INVALID_HANDLE_VALUE) {
        pipe = CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const auto error = GetLastError();
        if (std::chrono::steady_clock::now() >= deadline) {
            report.step = "connect_timeout"; report.error = error; return ClientStatus::Unavailable;
        }
        if (error == ERROR_PIPE_BUSY) { WaitNamedPipeW(pipe_name.c_str(), 200); continue; }
        if (error == ERROR_FILE_NOT_FOUND && !spawned) {
            PROCESS_INFORMATION process{};
            if (!SetEnvironmentVariableW(BrokerPipeEnvironment, pipe_name.c_str()) ||
                !SpawnRole(L"broker", nullptr, nullptr, process)) {
                report.step = "spawn_broker"; report.error = GetLastError(); return ClientStatus::Unavailable;
            }
            CloseHandle(process.hThread); CloseHandle(process.hProcess);
            spawned = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    // The plugin protocol is strictly request/response, so one thread relays
    // both directions. Synchronous I/O on a pipe handle is serialized: a
    // reader thread blocked on this handle would stall every request write.
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    for (;;) {
        std::string request, response;
        const auto frame = ReadFrame(input, request);
        if (frame == FrameStatus::End) break;
        const auto fail = [&](const char* step) {
            report.step = step; report.error = GetLastError(); CloseHandle(pipe); return ClientStatus::Failed;
        };
        if (frame != FrameStatus::Ok) return fail("compiler_read");
        report.last_command = FirstCommand(request);
        if (!WriteFrame(pipe, request)) return fail("broker_write");
        // A broken broker leaves the compiler with EOF, as a dedicated server would.
        if (ReadFrame(pipe, response) != FrameStatus::Ok) return fail("broker_read");
        if (!WriteFrame(output, response)) return fail("compiler_write");
        ++report.frames;
    }
    CloseHandle(pipe);
    return ClientStatus::Served;
}

} // namespace OpenFruit::MacroHost
