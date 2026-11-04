#include "win32_process.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <stdexcept>
using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool good, const char* message) { if (!good) throw std::runtime_error(message); }
BOOL WINAPI IgnoreControl(DWORD event) { return event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT; }
int CompilerStage(const fs::path& lock) {
    SetConsoleCtrlHandler(IgnoreControl, TRUE); // Only the CLI/supervisor may terminate this owned fixture.
    HANDLE file = CreateFileW(lock.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(file != INVALID_HANDLE_VALUE, "Owned compiler fixture cannot open lock");
    std::cout << "owned-compiler=" << GetCurrentProcessId() << '\n' << std::flush;
    Sleep(INFINITE); CloseHandle(file); return 99;
}
int Driver(const fs::path& self, const fs::path& cli, const fs::path& root, const std::string& mode) {
    Require(GetConsoleCP() != 0, "Owned test console was not created");
    Require(SetConsoleCtrlHandler(IgnoreControl, TRUE), "Cannot protect isolated test driver");
    fs::create_directories(root);
    const auto lock = root / "compiler.lock";
    bool sent = false;
    std::thread signal([&] {
        for (int attempt = 0; attempt < 300 && !fs::exists(lock); ++attempt) Sleep(10);
        if (fs::exists(lock)) sent = GenerateConsoleCtrlEvent(mode.starts_with("break") ? CTRL_BREAK_EVENT : CTRL_C_EVENT, 0) != FALSE;
    });
    ProcessRunOptions options; options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    std::vector<std::wstring> arguments{cli.wstring(), L"--wait", lock.wstring()};
    if (mode.ends_with("json")) arguments.push_back(L"--diagnostics=json");
    // Prebuilt owned compiler is input outside the cancellation behavior under
    // test. Real CLI/proxy/console handler/Job Object provide all control values.
    const auto result = Win32Process::Run(cli.wstring(), arguments, L"",
        {{L"OPENFRUIT_USER_STATE", (root / "state").wstring()},
         {L"OPENFRUIT_COMPILER_PROXY_REAL", self.wstring()},
         {L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L""}, {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", L""}}, nullptr, nullptr, options);
    signal.join();
    Require(sent && result.launched && !result.timed_out && result.exit_code == 130, "Actual CLI did not cooperatively terminate after console cancellation");
    HANDLE reopened = CreateFileW(lock.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(reopened != INVALID_HANDLE_VALUE, "Cancelled compiler retained its lock"); CloseHandle(reopened);
    int cancelling = 0; bool command_cancelled = false, process_cancelled = false;
    for (const auto& item : fs::recursive_directory_iterator(root / "state")) {
        if (item.path().filename() != "events.jsonl") continue;
        std::ifstream records(item.path()); std::string line;
        while (std::getline(records, line)) {
            const auto record = JsonValue::Parse(line); Require(record.has_value(), "Cancellation journal contains invalid JSON");
            if (record->GetString("kind") == "operation.cancelling") ++cancelling;
            const auto data = record->Get("data");
            if (data) {
                command_cancelled |= data->GetString("name") == "cli.command" && data->GetString("state") == "cancelled" && data->Get("exit_code") && data->Get("exit_code")->Int() == 130;
                process_cancelled |= data->GetString("exit_kind") == "cancelled";
            }
        }
    }
    Require(cancelling == 1 && command_cancelled && process_cancelled, "Cancellation was duplicated or reported as an ordinary failure");
    if (mode.ends_with("json")) {
        std::istringstream records(result.std_out); std::string line; bool terminal = false;
        while (std::getline(records, line)) {
            const auto event = JsonValue::Parse(line); Require(event.has_value(), "Cancelled JSON CLI polluted stdout");
            const auto data = event->Get("data");
            terminal |= data && data->GetString("name") == "cli.command" && data->GetString("state") == "cancelled";
        }
        Require(terminal, "Live stream lost terminal cancellation");
    }
    std::cout << "PASS: " << mode << '\n'; return 0;
}
struct NativeHandle { HANDLE value = nullptr; ~NativeHandle() { if (value) CloseHandle(value); } };
void RunHiddenConsole(const fs::path& self, const fs::path& cli, const fs::path& root, const std::string& mode) {
    NativeHandle job{CreateJobObjectW(nullptr, nullptr)};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Require(job.value && SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)), "Cannot own isolated console test subtree");
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    auto command = Win32Process::BuildCommandLine({self.wstring(), L"--driver", cli.wstring(), root.wstring(), Win32Process::ToWide(mode)});
    Require(CreateProcessW(self.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        nullptr, nullptr, &startup, &process), "Cannot create isolated hidden console");
    NativeHandle child{process.hProcess}, thread{process.hThread};
    if (!AssignProcessToJobObject(job.value, child.value)) { TerminateProcess(child.value, 9); throw std::runtime_error("Cannot assign isolated console ownership"); }
    Require(ResumeThread(thread.value) != DWORD(-1), "Cannot resume owned console");
    Require(WaitForSingleObject(child.value, 15000) == WAIT_OBJECT_0, "Isolated console test did not terminate");
    DWORD exit = 99; Require(GetExitCodeProcess(child.value, &exit) && exit == 0, "Real console/CLI cancellation integration failed");
}
}
int main(int argc, char** argv) {
    try {
        const auto self = fs::absolute(argv[0]);
        if (argc == 3 && std::string(argv[1]) == "--wait") return CompilerStage(fs::path(argv[2]));
        if (argc == 5 && std::string(argv[1]) == "--driver") return Driver(self, fs::path(argv[2]), fs::path(argv[3]), argv[4]);
        Require(argc == 2, "Expected actual native CLI path");
        const auto root = fs::temp_directory_path() / ("OPENFRUIT-console-control-" + NewOperationId());
        for (const auto* mode : {"ctrlc-normal", "ctrlc-json", "break-normal", "break-json"})
            RunHiddenConsole(self, fs::absolute(argv[1]), root / mode, mode);
        std::cout << "Real isolated Ctrl+C/Ctrl+Break -> actual CLI -> owned process cancellation: PASS\n";
        std::cout << "Evidence: " << root.string() << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
