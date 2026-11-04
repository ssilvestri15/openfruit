#include "json_value.hpp"
#include "darwin_image.hpp"
#include "win32_process.hpp"
#include "darwin_macro_provider.hpp"
#include "darwin_arm64.hpp"
#include "tool_paths.hpp"
#include "transport.hpp"
#include "budget.hpp"
#include "broker.hpp"
#include "content_hash.hpp"
#include <limits>
#include <iterator>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
using OpenFruit::JsonValue;
namespace {
using OpenFruit::MacroHost::FrameStatus;
using OpenFruit::MacroHost::ReadFrame;
bool WriteFrame(HANDLE output, const JsonValue& response) {
    return OpenFruit::MacroHost::WriteFrame(output, response.Serialize());
}
JsonValue UnsupportedDiagnostic(const std::string& message = "OPENFRUIT native macro execution is unavailable: no original-plugin runtime backend is configured.") {
    auto position = JsonValue::ObjectValue();
    position.Set("fileName", JsonValue::String(""));
    position.Set("offset", JsonValue::Number("0"));
    auto diagnostic = JsonValue::ObjectValue();
    diagnostic.Set("message", JsonValue::String(message));
    diagnostic.Set("severity", JsonValue::String("error"));
    diagnostic.Set("position", std::move(position));
    diagnostic.Set("highlights", JsonValue::ArrayValue());
    diagnostic.Set("notes", JsonValue::ArrayValue());
    diagnostic.Set("fixIts", JsonValue::ArrayValue());
    return diagnostic;
}
std::wstring Environment(const wchar_t* key, bool* present = nullptr) {
    SetLastError(ERROR_SUCCESS);
    const auto size = GetEnvironmentVariableW(key, nullptr, 0);
    if (present) *present = size != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    if (!size) return {};
    std::wstring value(size, L'\0');
    const auto count = GetEnvironmentVariableW(key, value.data(), size);
    if (!count || count >= size) return {};
    value.resize(count); return value;
}
// Abnormal guest stops keep the complete bootstrap report (stop PC, faulting
// address/type, recent instructions, syscall prefixes) under the user
// diagnostic root. The compiler only receives a one-line summary on stderr.
std::string WriteRuntimeStopReport(const JsonValue& bootstrap, const std::string& diagnostic) {
    namespace fs = std::filesystem;
    try {
        const auto root = OpenFruit::ToolPaths::UserStateRoot() / "diagnostics" / "macro-runtime";
        std::error_code ignored;
        fs::create_directories(root, ignored);
        SYSTEMTIME now{}; GetLocalTime(&now);
        char stamp[64] = {};
        std::snprintf(stamp, sizeof(stamp), "%04u%02u%02u-%02u%02u%02u-%03u-%lu.json",
                      now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
                      now.wMilliseconds, static_cast<unsigned long>(GetCurrentProcessId()));
        const auto path = root / stamp;
        auto document = JsonValue::ObjectValue();
        document.Set("schema", JsonValue::String("openfruit.macro-runtime-stop.v1"));
        document.Set("diagnostic", JsonValue::String(diagnostic));
        document.Set("bootstrap", bootstrap);
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << document.Serialize(true) << '\n';
        if (!output) return {};
        return OpenFruit::Win32Process::ToNarrow(path.wstring());
    } catch (...) {
        return {};
    }
}
// One JSON line per original-provider session (admission, broker and runtime
// outcome). The compiler does not surface plugin stderr in build logs.
void AppendSessionRecord(JsonValue record) {
    try {
        const auto root = OpenFruit::ToolPaths::UserStateRoot() / "diagnostics" / "macro-runtime";
        std::error_code ignored;
        std::filesystem::create_directories(root, ignored);
        record.Set("pid", JsonValue::Number(std::to_string(GetCurrentProcessId())));
        SYSTEMTIME now{}; GetLocalTime(&now);
        char stamp[32] = {};
        std::snprintf(stamp, sizeof(stamp), "%02u:%02u:%02u.%03u", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
        record.Set("time", JsonValue::String(stamp));
        const auto line = record.Serialize() + "\n";
        const auto path = (root / "sessions.jsonl").wstring();
        const HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(file);
    } catch (...) {}
}
// A pooled worker is admitted by its broker's pool size instead of the global
// per-session budget, and serves successive compiler sessions on one stream.
int RunOriginalProvider(const std::wstring& receipt, bool pooled = false) {
    using namespace OpenFruit;
    DarwinClosureOptions options;
    // Diagnostic probes have a whole-session instruction cap; compiler sessions
    // use existing finite CPU slices with operation cancellation/deadline instead.
    options.instruction_limit = std::numeric_limits<std::size_t>::max();
    const auto context = CurrentOperationContext();
    if (context && context->control) options.deadline = context->control->deadline;
    DarwinMacroProvider provider; std::string error;
    if (!ReadDarwinMacroProvider(receipt, ToolPaths::LocalHome(), provider, error, {}, options)) {
        std::cerr << "Invalid managed macro provider: " << error << '\n'; return 2;
    }
    const auto selection = Win32Process::ToNarrow(Environment(kDarwinMacroModulesEnvironment));
    std::map<std::string, std::string> catalog, modules;
    for (const auto& plugin : provider.plugins) catalog.emplace(plugin.module, plugin.virtual_path);
    std::vector<std::string> plugins;
    if (!MacroHost::SelectModules(selection, catalog, modules, plugins)) {
        std::cerr << "Unknown, empty or duplicate managed macro module selection.\n"; return 2;
    }
    const auto budget_namespace = MacroHost::BudgetNamespace(provider.managed_root);
    if (!budget_namespace) { std::cerr << "Cannot identify managed macro session budget root.\n"; return 2; }
    MacroHost::SessionBudget budget;
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed_ms = [&] {
        return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    };
    auto record = JsonValue::ObjectValue();
    record.Set("modules", JsonValue::String(selection));
    record.Set("role", JsonValue::String(pooled ? "worker" : "direct"));
    const auto admitted = pooled ? MacroHost::BudgetStatus::Acquired : budget.Acquire(*budget_namespace,
        [&] { return context && (context->CancellationRequested() || context->DeadlineExceeded()); },
        GetStdHandle(STD_INPUT_HANDLE));
    record.Set("admission", JsonValue::String(pooled ? "pooled" : admitted == MacroHost::BudgetStatus::Acquired ? "acquired" :
        admitted == MacroHost::BudgetStatus::Cancelled ? "cancelled" :
        admitted == MacroHost::BudgetStatus::InputClosed ? "input_closed" : "failed"));
    record.Set("admission_wait_ms", JsonValue::Number(elapsed_ms()));
    record.Set("abandoned_slot_recovered", JsonValue::Boolean(budget.AbandonedOwnerRecovered()));
    if (admitted != MacroHost::BudgetStatus::Acquired) AppendSessionRecord(record);
    if (admitted == MacroHost::BudgetStatus::Cancelled) return 130;
    if (admitted == MacroHost::BudgetStatus::InputClosed) return 0;
    if (admitted != MacroHost::BudgetStatus::Acquired) { std::cerr << "Cannot acquire native macro session budget.\n"; return 2; }
    // Main thread retains/releases its mutex ownership through cache and guest
    // lifetime. Terminated processes abandon ownership rather than losing a slot.
    options.shared_cache = DyldCacheView::Open(provider.parent_cache_report, provider.child_cache_reports,
                                               error, options.cancellation, options.deadline);
    if (!options.shared_cache) {
        record.Set("diagnostic", JsonValue::String("Original macro cache is unavailable: " + error));
        AppendSessionRecord(record);
        std::cerr << "Original macro cache is unavailable: " << error << '\n'; return 2;
    }
    const auto session = MacroHost::RunSession(GetStdHandle(STD_INPUT_HANDLE), modules,
        [&](const std::string& path, std::string& mapped) { return provider.TranslateLibraryPath(path, mapped); },
        [&](HANDLE input, CancellationToken cancellation) {
            OperationBinding binding(context);
            auto run_options = options; run_options.cancellation = cancellation;
            DarwinProcessStreams streams{input, GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE)};
            const auto result = MapDarwinArm64Images(provider.executable, provider.original_trees,
                                                     run_options, plugins, true, true, streams);
            const auto* status = result.bootstrap.Get("exit_status");
            if (result.mapped && result.bootstrap.GetString("stop_reason") == "exited" && status && status->IsNumber())
                return status->Int(-1) == 0 ? 0 : 1;
            std::cerr << "Original macro runtime stopped: " << result.bootstrap.GetString("stop_reason")
                      << ": " << result.diagnostic << '\n';
            const auto report = WriteRuntimeStopReport(result.bootstrap, result.diagnostic);
            if (!report.empty()) std::cerr << "Original macro runtime report: " << report << '\n';
            return 1;
        }, [&] { return context && (context->CancellationRequested() || context->DeadlineExceeded()); });
    record.Set("session_ms", JsonValue::Number(elapsed_ms()));
    record.Set("frames", JsonValue::Number(std::to_string(session.frames)));
    record.Set("last_command", JsonValue::String(session.last_command));
    record.Set("runtime_exit", JsonValue::Number(std::to_string(session.runtime_exit)));
    record.Set("broker_failed", JsonValue::Boolean(session.broker_failed));
    record.Set("cancelled", JsonValue::Boolean(session.cancelled));
    record.Set("diagnostic", JsonValue::String(session.diagnostic));
    AppendSessionRecord(record);
    if (!session.diagnostic.empty()) std::cerr << session.diagnostic << '\n';
    if (session.cancelled) return 130;
    if (session.broker_failed) return 2;
    return session.runtime_exit;
}

// The file system's own spelling of a path: one file launched through
// differently cased or aliased paths must yield one broker identity.
std::wstring FinalPath(const std::wstring& path) {
    const HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    std::wstring final(MAX_PATH * 4, L'\0');
    const auto length = GetFinalPathNameByHandleW(file, final.data(), static_cast<DWORD>(final.size()), FILE_NAME_NORMALIZED);
    CloseHandle(file);
    if (!length || length >= final.size()) return {};
    final.resize(length);
    return final;
}
// Brokers are scoped by OPENFRUIT (per user) and keyed by this executable's
// identity and the provider selection, so only identically configured hosts
// share warm servers.
std::wstring BrokerPipeName(const std::wstring& receipt) {
    using namespace OpenFruit;
    const auto scope = Environment(MacroHost::BrokerScopeEnvironment);
    if (scope.empty()) return {};
    wchar_t module[MAX_PATH * 4] = {};
    const auto length = GetModuleFileNameW(nullptr, module, static_cast<DWORD>(std::size(module)));
    if (!length || length >= std::size(module)) return {};
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (!GetFileAttributesExW(module, GetFileExInfoStandard, &attributes)) return {};
    const auto receipt_path = FinalPath(receipt), module_path = FinalPath(std::wstring(module, length));
    if (receipt_path.empty() || module_path.empty()) return {};
    const std::wstring identity = scope + L"\n" + receipt_path + L"\n" + Environment(kDarwinMacroModulesEnvironment) +
        L"\n" + module_path + L"\n" + std::to_wstring(attributes.ftLastWriteTime.dwHighDateTime) + L":" +
        std::to_wstring(attributes.ftLastWriteTime.dwLowDateTime) + L":" + std::to_wstring(attributes.nFileSizeLow);
    const auto digest = Sha256(Win32Process::ToNarrow(identity));
    if (!digest) return {};
    return L"\\\\.\\pipe\\OPENFRUIT-macro-broker-v2-" + Win32Process::ToWide(digest->substr(0, 32));
}
// Content-addressed responses of the original servers. Swift macro expansion
// is required to be a pure function of the request; the key covers the
// request, the client's capability and loaded libraries, the provider receipt
// bytes, the module selection and this host binary, so any change to the
// plugin, its inputs or the runtime misses. OPENFRUIT_MACRO_EXPANSION_CACHE=0
// disables it.
// Canonical text of a request for keying only (the original request is what
// the server receives). Object members are unordered in JSON. The compiler's
// staticBuildConfiguration is a separately encoded document whose string
// arrays are Swift Sets (swift-syntax decodes them as Set<String>), emitted in
// per-process hash order; they are keyed sorted. Other arrays keep order.
std::string CanonicalJson(const OpenFruit::JsonValue& value, bool string_sets) {
    using OpenFruit::JsonValue;
    if (value.IsObject()) {
        std::vector<std::pair<std::string, const JsonValue*>> members;
        for (const auto& [key, member] : value.ObjectItems()) members.emplace_back(key, &member);
        std::sort(members.begin(), members.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        std::string text = "{";
        for (const auto& [key, member] : members) {
            if (text.size() > 1) text += ",";
            text += JsonValue::String(key).Serialize() + ":";
            if (!string_sets && key == "staticBuildConfiguration" && member->IsString()) {
                const auto configuration = JsonValue::Parse(member->StringValue());
                text += configuration ? "C" + CanonicalJson(*configuration, true) : member->Serialize();
            } else {
                text += CanonicalJson(*member, string_sets);
            }
        }
        return text + "}";
    }
    if (value.IsArray()) {
        std::vector<std::string> items;
        bool strings = true;
        for (const auto& item : value.ArrayItems()) { items.push_back(CanonicalJson(item, string_sets)); strings = strings && item.IsString(); }
        if (string_sets && strings) std::sort(items.begin(), items.end());
        std::string text = "[";
        for (const auto& item : items) { if (text.size() > 1) text += ","; text += item; }
        return text + "]";
    }
    return value.Serialize();
}
class ExpansionCache {
public:
    bool Initialize(const std::wstring& receipt) {
        using namespace OpenFruit;
        if (Environment(L"OPENFRUIT_MACRO_EXPANSION_CACHE") == L"0") return false;
        wchar_t module[MAX_PATH * 4] = {};
        const auto length = GetModuleFileNameW(nullptr, module, static_cast<DWORD>(std::size(module)));
        if (!length || length >= std::size(module)) return false;
        const auto host = Sha256File(std::filesystem::path(std::wstring(module, length)));
        const auto provider = Sha256File(std::filesystem::path(receipt));
        if (!host || !provider) return false;
        identity_ = "openfruit.macro-expansion.v2\n" + *host + "\n" + *provider + "\n" +
                    Win32Process::ToNarrow(Environment(kDarwinMacroModulesEnvironment)) + "\n";
        root_ = ToolPaths::CacheRoot() / "macro-expansions" / "v2";
        return true;
    }
    std::string Key(const std::string& capability, const std::vector<std::string>& loads, const std::string& request) const {
        std::string material = identity_;
        const auto parsed = OpenFruit::JsonValue::Parse(request);
        if (!parsed) return {};
        const auto canonical = CanonicalJson(*parsed, false);
        for (const auto* part : {&capability, &canonical}) {
            material += std::to_string(part->size()) + ":" + *part + "\n";
            if (part == &capability)
                for (const auto& load : loads) material += std::to_string(load.size()) + ":" + load + "\n";
        }
        const auto digest = OpenFruit::Sha256(material);
        return digest ? *digest : std::string{};
    }
    std::optional<std::string> Load(const std::string& key) {
        {
            std::lock_guard lock(mutex_);
            if (const auto found = memory_.find(key); found != memory_.end()) return found->second;
        }
        std::ifstream input(Path(key), std::ios::binary);
        if (!input) return std::nullopt;
        std::string response((std::istreambuf_iterator<char>(input)), {});
        if (input.bad() || OpenFruit::MacroHost::FirstCommand(response) != "expandMacroResult") return std::nullopt;
        input.close();
        // The file's time records its last use; `cache clean` prunes unused ones.
        std::error_code ignored;
        std::filesystem::last_write_time(Path(key), std::filesystem::file_time_type::clock::now(), ignored);
        std::lock_guard lock(mutex_);
        memory_.emplace(key, response);
        return response;
    }
    void Store(const std::string& key, const std::string& response) {
        {
            std::lock_guard lock(mutex_);
            memory_.emplace(key, response);
        }
        // Publish atomically so a concurrent reader never sees a partial file.
        try {
            const auto path = Path(key);
            std::error_code ignored;
            std::filesystem::create_directories(path.parent_path(), ignored);
            auto temporary = path; temporary += L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
            {
                std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
                output.write(response.data(), static_cast<std::streamsize>(response.size()));
                if (!output) { std::filesystem::remove(temporary, ignored); return; }
            }
            if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) std::filesystem::remove(temporary, ignored);
        } catch (...) {}
    }
private:
    std::filesystem::path Path(const std::string& key) const {
        return root_ / key.substr(0, 2) / (key + ".frame");
    }
    std::string identity_;
    std::filesystem::path root_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::string> memory_;
};
int RunBroker(std::chrono::seconds idle = std::chrono::seconds(120)) {
    using namespace OpenFruit;
    const auto pipe = Environment(MacroHost::BrokerPipeEnvironment);
    if (pipe.empty()) return 2;
    std::size_t pool_size = 4;
    try { if (const auto value = Environment(MacroHost::PoolSizeEnvironment); !value.empty()) pool_size = std::stoul(value); }
    catch (...) {}
    MacroHost::Broker broker(pool_size);
    ExpansionCache cache;
    if (cache.Initialize(Environment(kDarwinMacroProviderEnvironment))) {
        broker.expansion_key = [&cache](const std::string& capability, const std::vector<std::string>& loads,
                                        const std::string& request) { return cache.Key(capability, loads, request); };
        broker.expansion_load = [&cache](const std::string& key) { return cache.Load(key); };
        broker.expansion_store = [&cache](const std::string& key, const std::string& response) { cache.Store(key, response); };
    }
    broker.on_exit = [pool_size](const MacroHost::BrokerStatistics& statistics) {
        auto record = JsonValue::ObjectValue();
        record.Set("role", JsonValue::String("broker"));
        record.Set("pool_size", JsonValue::Number(std::to_string(pool_size)));
        record.Set("clients", JsonValue::Number(std::to_string(statistics.clients)));
        record.Set("requests", JsonValue::Number(std::to_string(statistics.requests)));
        record.Set("replays", JsonValue::Number(std::to_string(statistics.replays)));
        record.Set("worker_starts", JsonValue::Number(std::to_string(statistics.worker_starts)));
        record.Set("worker_failures", JsonValue::Number(std::to_string(statistics.worker_failures)));
        record.Set("cache_hits", JsonValue::Number(std::to_string(statistics.cache_hits)));
        record.Set("cache_stores", JsonValue::Number(std::to_string(statistics.cache_stores)));
        AppendSessionRecord(record);
    };
    broker.on_worker_failure = [](const std::string& command, const std::string& step, DWORD exit_code) {
        auto record = JsonValue::ObjectValue();
        record.Set("role", JsonValue::String("broker_worker_failure"));
        record.Set("command", JsonValue::String(command));
        record.Set("step", JsonValue::String(step));
        record.Set("worker_exit", JsonValue::Number(std::to_string(exit_code)));
        AppendSessionRecord(record);
    };
    try {
        const auto root = ToolPaths::UserStateRoot() / "diagnostics" / "macro-runtime";
        std::error_code ignored;
        std::filesystem::create_directories(root, ignored);
        broker.worker_error_log = (root / "workers.log").wstring();
    } catch (...) {}
    // False means another broker already owns the name; its clients are served there.
    broker.Serve(pipe, idle);
    return 0;
}
// Started by OPENFRUIT outside any build job: becomes the persistent broker
// for this configuration unless one already serves it. A serving broker gets
// an empty client connection instead, which restarts its idle clock.
int RunPrewarm(const std::wstring& receipt) {
    using namespace OpenFruit;
    const auto pipe = BrokerPipeName(receipt);
    if (pipe.empty()) return 2;
    const HANDLE existing = CreateFileW(pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (existing != INVALID_HANDLE_VALUE) { CloseHandle(existing); return 0; }
    if (GetLastError() != ERROR_FILE_NOT_FOUND) return 0;
    if (!SetEnvironmentVariableW(MacroHost::BrokerPipeEnvironment, pipe.c_str())) return 2;
    SetEnvironmentVariableW(MacroHost::RoleEnvironment, nullptr);
    std::size_t idle_seconds = 900;
    try { if (const auto value = Environment(L"OPENFRUIT_MACRO_BROKER_IDLE_SECONDS"); !value.empty()) idle_seconds = std::stoul(value); }
    catch (...) {}
    return RunBroker(std::chrono::seconds(idle_seconds));
}
}
int main() {
    bool configured = false;
    const auto receipt = Environment(OpenFruit::kDarwinMacroProviderEnvironment, &configured);
    const auto role = Environment(OpenFruit::MacroHost::RoleEnvironment);
    if (role == L"broker") return RunBroker();
    if (configured) {
        if (receipt.empty()) { std::cerr << "Managed macro provider receipt is empty.\n"; return 2; }
        if (role == L"prewarm") return RunPrewarm(receipt);
        if (role == L"worker") {
            try { return RunOriginalProvider(receipt, true); }
            catch (const std::exception& failure) { std::cerr << "Managed macro provider failed: " << failure.what() << '\n'; return 2; }
        }
        const auto pipe = BrokerPipeName(receipt);
        if (!pipe.empty()) {
            OpenFruit::MacroHost::ClientReport report;
            const auto started = std::chrono::steady_clock::now();
            const auto status = OpenFruit::MacroHost::RunClient(pipe, std::chrono::seconds(60), report);
            if (status != OpenFruit::MacroHost::ClientStatus::Served) {
                using OpenFruit::JsonValue;
                auto record = JsonValue::ObjectValue();
                record.Set("role", JsonValue::String("client"));
                record.Set("status", JsonValue::String(status == OpenFruit::MacroHost::ClientStatus::Failed ? "failed" : "unavailable"));
                record.Set("step", JsonValue::String(report.step));
                record.Set("win32_error", JsonValue::Number(std::to_string(report.error)));
                record.Set("frames", JsonValue::Number(std::to_string(report.frames)));
                record.Set("last_command", JsonValue::String(report.last_command));
                record.Set("session_ms", JsonValue::Number(std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started).count())));
                AppendSessionRecord(record);
            }
            if (status == OpenFruit::MacroHost::ClientStatus::Served) return 0;
            if (status == OpenFruit::MacroHost::ClientStatus::Failed) return 1;
        }
        try { return RunOriginalProvider(receipt); }
        catch (const std::exception& failure) { std::cerr << "Managed macro provider failed: " << failure.what() << '\n'; return 2; }
    }
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    std::string message;
    for (;;) {
        const auto frame = ReadFrame(input, message);
        if (frame == FrameStatus::End) return 0;
        if (frame == FrameStatus::Error) { std::cerr << "Invalid or truncated macro protocol frame.\n"; return 2; }
        const auto request = JsonValue::Parse(message);
        if (!request || !request->IsObject() || request->ObjectItems().size() != 1) {
            std::cerr << "Invalid macro protocol message.\n"; return 2;
        }
        const auto& command = request->ObjectItems().begin()->first;
        if (!request->ObjectItems().begin()->second.IsObject()) {
            std::cerr << "Invalid macro protocol payload.\n"; return 2;
        }
        auto result = JsonValue::ObjectValue(), response = JsonValue::ObjectValue();
        if (command == "getCapability") {
            auto capability = JsonValue::ObjectValue();
            capability.Set("protocolVersion", JsonValue::Number("7"));
            capability.Set("features", JsonValue::ArrayValue());
            result.Set("capability", std::move(capability));
            response.Set("getCapabilityResult", std::move(result));
        } else if (command == "loadPluginLibrary") {
            auto diagnostic = UnsupportedDiagnostic();
            const auto path = request->Get(command)->GetString("libraryPath");
            OpenFruit::DarwinImage image;
            std::string error;
            if (path.empty() || !OpenFruit::ReadDarwinImage(OpenFruit::Win32Process::ToWide(path), image, error))
                diagnostic = UnsupportedDiagnostic("OPENFRUIT native macro image preflight failed: " + (path.empty() ? "missing libraryPath." : error));
            else diagnostic = UnsupportedDiagnostic("OPENFRUIT inspected original Mach-O host slice (CPU " +
                std::to_string(image.cpu) + ", SHA-256 " + image.sha256 + ", " + std::to_string(image.dependencies.size()) +
                " dependency load commands); native Darwin loader/runtime backend is not configured.");
            result.Set("loaded", JsonValue::Boolean(false));
            result.Set("diagnostics", JsonValue::ArrayValue({std::move(diagnostic)}));
            response.Set("loadPluginLibraryResult", std::move(result));
        } else if (command == "expandFreestandingMacro") {
            auto diagnostic = UnsupportedDiagnostic();
            result.Set("expandedSource", JsonValue::Null());
            result.Set("diagnostics", JsonValue::ArrayValue({std::move(diagnostic)}));
            response.Set("expandFreestandingMacroResult", std::move(result));
        } else if (command == "expandAttachedMacro") {
            auto diagnostic = UnsupportedDiagnostic();
            result.Set("expandedSources", JsonValue::Null());
            result.Set("diagnostics", JsonValue::ArrayValue({std::move(diagnostic)}));
            response.Set("expandAttachedMacroResult", std::move(result));
        } else {
            std::cerr << "Unsupported macro protocol message.\n"; return 2;
        }
        if (!WriteFrame(output, response)) { std::cerr << "Macro protocol write failed.\n"; return 3; }
    }
}
