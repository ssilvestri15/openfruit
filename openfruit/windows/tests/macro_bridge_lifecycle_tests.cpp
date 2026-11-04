#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>
#include <stdexcept>
namespace fs = std::filesystem;
using namespace OpenFruit;
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::wstring Env(const wchar_t* name) {
    const auto size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring text(size, L'\0');
    text.resize(GetEnvironmentVariableW(name, text.data(), size)); return text;
}
struct Environment {
    std::vector<std::pair<std::wstring, std::wstring>> previous;
    void Set(const wchar_t* name, const std::wstring& value) {
        previous.emplace_back(name, Env(name));
        SetEnvironmentVariableW(name, value.empty() ? nullptr : value.c_str());
    }
    ~Environment() { for (auto it = previous.rbegin(); it != previous.rend(); ++it)
        SetEnvironmentVariableW(it->first.c_str(), it->second.empty() ? nullptr : it->second.c_str()); }
};
std::string Read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary); return {std::istreambuf_iterator<char>(file), {}};
}
std::string Frame(const std::string& text) {
    const std::uint64_t size = text.size();
    return std::string(reinterpret_cast<const char*>(&size), 8) + text;
}
// This executable is copied as wsl.exe beside the owned bridge. Windows resolves
// that private module before system WSL; no Linux provider or upstream plugin runs.
int ProviderFixture(int argc, wchar_t** argv) {
    auto call = JsonValue::ArrayValue();
    for (int i = 1; i < argc; ++i) call.ArrayItems().push_back(JsonValue::String(Win32Process::ToNarrow(argv[i])));
    { std::ofstream log(fs::path(Env(L"OPENFRUIT_OWNED_PROVIDER_LOG")), std::ios::app);
      if (!log) return 80; log << call.Serialize() << '\n'; }
    // A baseline global shutdown would stop only this independently owned
    // sentinel. This makes the old defect observable without touching WSL.
    for (int i = 1; i < argc; ++i) if (std::wstring(argv[i]).find(L"shutdown") != std::wstring::npos) {
        Handle sentinel{OpenProcess(PROCESS_TERMINATE, FALSE,
            static_cast<DWORD>(std::stoul(Env(L"OPENFRUIT_OWNED_SENTINEL_PID"))))};
        if (sentinel.value) TerminateProcess(sentinel.value, 81);
        return 0;
    }
    return 82; // Server unavailable, including handshake and readiness probes.
}
std::vector<JsonValue> Exchange(const fs::path& bridge, const fs::path& root, HANDLE job) {
    const auto input_bytes = Frame(R"({"getCapability":{}})") +
        Frame(R"({"loadPluginLibrary":{"libraryPath":"C:\\owned\\ObservationMacros.dll","moduleName":"ObservationMacros"}})");
    { std::ofstream file(root / "input", std::ios::binary); file << input_bytes; }
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle input{CreateFileW((root / "input").c_str(), GENERIC_READ, FILE_SHARE_READ,
        &security, OPEN_EXISTING, 0, nullptr)};
    Handle output{CreateFileW((root / "output").c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        &security, CREATE_ALWAYS, 0, nullptr)};
    Handle errors{CreateFileW((root / "errors").c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        &security, CREATE_ALWAYS, 0, nullptr)};
    Require(input.value != INVALID_HANDLE_VALUE && output.value != INVALID_HANDLE_VALUE &&
        errors.value != INVALID_HANDLE_VALUE, "exchange handles unavailable");
    STARTUPINFOW start{}; start.cb = sizeof(start); start.dwFlags = STARTF_USESTDHANDLES;
    start.hStdInput = input.value; start.hStdOutput = output.value; start.hStdError = errors.value;
    PROCESS_INFORMATION info{}; auto command = Win32Process::QuoteArgument(bridge.wstring());
    Require(CreateProcessW(bridge.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, root.c_str(), &start, &info), "bridge launch failed");
    Handle process{info.hProcess}, thread{info.hThread};
    if (!AssignProcessToJobObject(job, process.value)) {
        TerminateProcess(process.value, 83); throw std::runtime_error("bridge job assignment failed");
    }
    Require(ResumeThread(thread.value) != DWORD(-1), "bridge resume failed");
    Require(WaitForSingleObject(process.value, 10000) == WAIT_OBJECT_0, "bridge timeout");
    DWORD exit = 1; Require(GetExitCodeProcess(process.value, &exit) && exit == 0, "bridge failed transport");
    std::vector<JsonValue> replies; const auto bytes = Read(root / "output");
    for (std::size_t offset = 0; offset < bytes.size();) {
        Require(bytes.size() - offset >= 8, "truncated header");
        std::uint64_t size = 0; std::memcpy(&size, bytes.data() + offset, 8); offset += 8;
        Require(size > 0 && size <= bytes.size() - offset, "truncated payload");
        auto reply = JsonValue::Parse(bytes.substr(offset, size));
        Require(reply.has_value(), "invalid reply JSON"); replies.push_back(*reply); offset += size;
    }
    return replies;
}
int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == L"-d") return ProviderFixture(argc, argv);
    if (argc == 3 && std::wstring(argv[1]) == L"--sentinel") {
        Handle lock{CreateFileW(argv[2], GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr)};
        if (lock.value == INVALID_HANDLE_VALUE) return 84;
        Sleep(INFINITE); return 0;
    }
    fs::path root;
    try {
        Require(argc == 2, "expected bridge path");
        root = fs::temp_directory_path() / ("OPENFRUIT-bridge-lifecycle-" + NewOperationId());
        const auto bin = root / "bin"; fs::create_directories(bin);
        const auto bridge = bin / "openfruit-macro-bridge.exe";
        fs::copy_file(fs::absolute(argv[1]), bridge);
        wchar_t self[32768]{};
        Require(GetModuleFileNameW(nullptr, self, 32768) > 0, "fixture executable missing");
        fs::copy_file(self, bin / "wsl.exe");
        Handle job{CreateJobObjectW(nullptr, nullptr)};
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(job.value && SetInformationJobObject(job.value, JobObjectExtendedLimitInformation,
            &limit, sizeof(limit)), "fixture job unavailable");
        const auto lock_path = root / "sentinel-lock";
        auto command = Win32Process::BuildCommandLine({self, L"--sentinel", lock_path.wstring()});
        STARTUPINFOW start{}; start.cb = sizeof(start); PROCESS_INFORMATION info{};
        Require(CreateProcessW(self, command.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, root.c_str(), &start, &info), "sentinel launch failed");
        Handle sentinel{info.hProcess}, thread{info.hThread};
        if (!AssignProcessToJobObject(job.value, sentinel.value)) {
            TerminateProcess(sentinel.value, 85); throw std::runtime_error("sentinel job failed");
        }
        Require(ResumeThread(thread.value) != DWORD(-1), "sentinel resume failed");
        for (int i = 0; i < 100 && !fs::exists(lock_path); ++i) Sleep(10);
        Require(fs::exists(lock_path), "sentinel did not acquire lock");
        Environment environment;
        environment.Set(L"OPENFRUIT_OWNED_PROVIDER_LOG", (root / "provider-calls").wstring());
        environment.Set(L"OPENFRUIT_OWNED_SENTINEL_PID", std::to_wstring(info.dwProcessId));
        environment.Set(L"OPENFRUIT_APPLE_PLUGIN_SERVER_RETRIES", L"2");
        environment.Set(L"OPENFRUIT_DISABLE_APPLE_PLUGIN_SERVER", L"0");
        environment.Set(L"OPENFRUIT_DARLING_BUNDLE", L"/owned bundle");
        environment.Set(L"OPENFRUIT_DARLING_PREFIX", L"/owned prefix");
        for (const auto& distro : {std::wstring(L"Owned Test Distro"), std::wstring{}}) {
            environment.Set(L"OPENFRUIT_WSL_DISTRO", distro);
            { std::ofstream clear(root / "provider-calls"); }
            const auto replies = Exchange(bridge, root, job.value);
            Require(replies.size() == 2, "protocol replies missing");
            const auto* load = replies.back().Get("loadPluginLibraryResult");
            Require(load && load->Get("loaded") && !load->Get("loaded")->Bool(true), "failed server declared loaded");
            const auto* diagnostics = load->Get("diagnostics");
            Require(diagnostics && diagnostics->ArrayItems().size() == 1 &&
                diagnostics->ArrayItems().front().GetString("severity") == "error", "failed server lacks explicit error");
            const auto& diagnostic = diagnostics->ArrayItems().front();
            for (const auto* field : {"highlights", "notes", "fixIts"})
                Require(diagnostic.Get(field) && diagnostic.Get(field)->IsArray(), "incomplete Swift diagnostic schema");
            std::ifstream calls(root / "provider-calls"); std::string line; int count = 0;
            const std::vector<std::string> expected = {"-d", distro.empty() ? "Ubuntu" : Win32Process::ToNarrow(distro),
                "--", "env", "DPREFIX=/owned prefix", "darling", "shell",
                "/owned bundle/toolchain/usr/bin/swift-plugin-server"};
            while (std::getline(calls, line)) {
                const auto call = JsonValue::Parse(line);
                Require(call && call->IsArray() && call->ArrayItems().size() == expected.size(), "unexpected provider lifecycle command");
                for (std::size_t i = 0; i < expected.size(); ++i)
                    Require(call->ArrayItems()[i].StringValue() == expected[i], "provider arguments/distribution changed");
                ++count;
            }
            Require(count == 2, "owned server retries missing or global provider commands added");
            Require(WaitForSingleObject(sentinel.value, 0) == WAIT_TIMEOUT, "unrelated owned sentinel stopped");
            Handle locked{CreateFileW(lock_path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr)};
            Require(locked.value == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
                "unrelated session lock released");
        }
        Require(TerminateJobObject(job.value, 0), "owned fixture cleanup failed");
        Require(WaitForSingleObject(sentinel.value, 5000) == WAIT_OBJECT_0, "sentinel cleanup timeout");
        fs::remove_all(root); // Only this newly reserved owned fixture.
        std::cout << "PASS: actual bridge retries its server only, preserves independent session, uses configured/default distro\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n'; return 1;
    }
}
