#include "win32_process.hpp"
#include "event_journal.hpp"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <future>
#include <thread>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* error) { if (!condition) throw std::runtime_error(error); }
int Child(int argc, char** argv) {
    const std::string mode = argv[1];
    if (mode == "--lock") {
        HANDLE file = CreateFileW(fs::path(argv[2]).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return 9;
        std::cout << "grandchild=" << GetCurrentProcessId() << '\n' << std::flush;
        Sleep(INFINITE);
        return 0;
    }
    if (mode == "--tree") {
        STARTUPINFOW info{}; info.cb = sizeof(info);
        info.dwFlags = STARTF_USESTDHANDLES;
        info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION process{};
        const auto exe = fs::absolute(argv[0]).wstring();
        auto command = Win32Process::BuildCommandLine({exe, L"--lock", fs::path(argv[2]).wstring()});
        Require(CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
            nullptr, nullptr, &info, &process), "Cannot create owned grandchild");
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        // Ensure grandchild actually opened the lock before a successful exit.
        for (int i = 0; i < 200 && !fs::exists(argv[2]); ++i) Sleep(10);
        if (argc >= 4 && std::string(argv[3]) == "exit") { Sleep(100); return 0; }
        Sleep(INFINITE); return 0;
    }
    if (mode == "--event") {
        const auto handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::stoull(argv[2])));
        return SetEvent(handle) ? 8 : 0;
    }
    if (mode == "--output") { std::cout << std::string(1024 * 1024, 'x'); return 0; }
    if (mode == "--survivor") { std::cout << "ready\n" << std::flush; Sleep(700); return 0; }
    if (mode == "--nested") {
        const auto exe = fs::absolute(argv[0]).wstring();
        return Win32Process::Run(exe, {exe, L"--output"}).success ? 0 : 7;
    }
    return 99;
}
void TestTree(const fs::path& executable, const fs::path& root, const std::string& mode) {
    const auto lock = root / (mode + ".lock");
    ProcessRunOptions options;
    options.cancellation = std::make_shared<std::atomic<bool>>(false);
    if (mode == "deadline") options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    std::string observed;
    const auto began = std::chrono::steady_clock::now();
    const auto result = Win32Process::Run(executable.wstring(),
        {executable.wstring(), L"--tree", lock.wstring(), mode == "normal" ? L"exit" : L"wait"}, L"", {},
        [&](const std::string& text) {
            observed += text;
            if (mode == "cancel" && observed.find("grandchild=") != std::string::npos) *options.cancellation = true;
        }, nullptr, options);
    Require(result.launched && observed.find("grandchild=") != std::string::npos, "Tree test did not launch grandchild");
    Require(std::chrono::steady_clock::now() - began < std::chrono::seconds(8), "Owned tree failed to drain promptly");
    if (mode == "normal") Require(result.success, "Successful parent changed outcome");
    if (mode == "cancel") Require(result.cancelled && !result.success, "Cancellation reported ordinary tool outcome");
    if (mode == "deadline") Require(result.timed_out && !result.success, "Deadline reported ordinary tool outcome");
    const DWORD pid = static_cast<DWORD>(std::stoul(observed.substr(observed.find("grandchild=") + 11)));
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (process) { Require(WaitForSingleObject(process, 5000) == WAIT_OBJECT_0, "Grandchild escaped process ownership"); CloseHandle(process); }
    HANDLE reopened = CreateFileW(lock.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(reopened != INVALID_HANDLE_VALUE, "Cancelled child retained file lock");
    CloseHandle(reopened);
}

void TestOperationPropagation(const fs::path& executable, const fs::path& root) {
    auto first = EventJournal::Create(root / "cancel-operation");
    auto second = EventJournal::Create(root / "survivor-operation");
    const auto cancel_context = first->Context();
    const auto survivor_context = second->Context();
    std::promise<void> ready;
    const auto ready_future = ready.get_future();
    ProcessResult survivor;
    std::jthread worker([&]() {
        OperationBinding binding(survivor_context);
        OperationSpan task("survivor.module");
        bool signalled = false;
        survivor = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--survivor"}, L"", {},
            [&](const std::string&) { if (!signalled) { signalled = true; ready.set_value(); } });
        task.Complete(JsonValue::ObjectValue(), survivor.success);
    });
    const bool sibling_running = ready_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    ProcessResult cancelled;
    {
        OperationBinding binding(cancel_context);
        OperationSpan parent("cancel.operation");
        OperationSpan module("cancel.module");
        const auto context = CurrentOperationContext();
        Require(context->control == cancel_context->control, "Nested span lost operation control");
        std::string received;
        cancelled = Win32Process::Run(executable.wstring(),
            {executable.wstring(), L"--tree", (root / "context.lock").wstring(), L"wait"}, L"", {},
            [&](const std::string& text) {
                received += text;
                if (received.find("grandchild=") != std::string::npos) {
                    cancel_context->RequestCancellation();
                    cancel_context->RequestCancellation();
                }
            });
        module.Complete(JsonValue::ObjectValue(), cancelled.success);
        parent.Complete(JsonValue::ObjectValue(), cancelled.success);
    }
    worker.join();
    Require(sibling_running && survivor.success && !survivor_context->CancellationRequested(),
        "Cancellation leaked into concurrent operation");
    Require(cancelled.launched && cancelled.cancelled && !cancelled.success,
        "Operation cancellation did not reach real process automatically");
    first->Flush();
    std::ifstream events(first->Directory() / "events.jsonl");
    std::string line; int cancelling = 0; bool module_cancelled = false;
    while (std::getline(events, line)) {
        const auto record = JsonValue::Parse(line);
        if (record->GetString("kind") == "operation.cancelling") ++cancelling;
        const auto data = record->Get("data");
        if (data && data->GetString("name") == "cancel.module" && data->GetString("state") == "cancelled") module_cancelled = true;
    }
    Require(cancelling == 1 && module_cancelled, "Duplicate cancelling event or lost parent cancellation state");

    auto deadline_context = std::make_shared<OperationContext>();
    deadline_context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() + std::chrono::milliseconds(100));
    OperationBinding binding(deadline_context); // No telemetry sink is needed for control propagation.
    OperationSpan task("deadline.module");
    const auto timed = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--survivor"});
    Require(timed.launched && timed.timed_out && !timed.success, "Sinkless operation deadline did not reach process");
    deadline_context->RequestCancellation();
    const auto refused = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--output"});
    Require(refused.cancelled && !refused.launched, "Cancelled operation launched another task process");
}
}
int main(int argc, char** argv) {
    try {
        if (argc > 1) return Child(argc, argv);
        const auto executable = fs::absolute(argv[0]);
        const auto root = fs::temp_directory_path() / ("OPENFRUIT-process-supervisor-" + NewOperationId());
        fs::create_directories(root);
        auto journal = EventJournal::Create(root / "events");
        OperationBinding binding(journal->Context());
        TestTree(executable, root, "cancel"); TestTree(executable, root, "deadline"); TestTree(executable, root, "normal");
        TestOperationPropagation(executable, root);
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE extra = CreateEventW(&attributes, TRUE, FALSE, nullptr);
        Require(extra != nullptr, "Cannot create extra inheritable handle");
        // Positive control: unrestricted inheritance must signal this actual
        // parent object. A child-local handle with the same number is not proof
        // that the parent event was inherited.
        STARTUPINFOW control_startup{};control_startup.cb=sizeof(control_startup);
        PROCESS_INFORMATION control_process{};
        auto control_command=Win32Process::BuildCommandLine({executable.wstring(),L"--event",
            std::to_wstring(reinterpret_cast<std::uintptr_t>(extra))});
        Require(CreateProcessW(executable.c_str(),control_command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,
            nullptr,nullptr,&control_startup,&control_process),"Cannot launch inheritance positive control");
        CloseHandle(control_process.hThread);
        const auto control_wait=WaitForSingleObject(control_process.hProcess,5000);
        DWORD control_exit=0;const auto control_status=GetExitCodeProcess(control_process.hProcess,&control_exit);
        CloseHandle(control_process.hProcess);
        Require(control_wait==WAIT_OBJECT_0&&control_status&&control_exit==8&&WaitForSingleObject(extra,0)==WAIT_OBJECT_0,
            "Inheritance positive control did not signal the actual parent event");
        Require(ResetEvent(extra),"Cannot reset positive-control event");
        const auto isolated = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--event",
            std::to_wstring(reinterpret_cast<std::uintptr_t>(extra))});
        Require(isolated.launched&&(isolated.exit_code==0||isolated.exit_code==8)&&!isolated.timed_out&&!isolated.cancelled
            &&WaitForSingleObject(extra,0)==WAIT_TIMEOUT,"Unrelated parent event leaked into child");
        CloseHandle(extra);
        Require(Win32Process::Run(executable.wstring(), {executable.wstring(), L"--nested"}).success,
            "Nested job environment failed");
        ProcessRunOptions limited; limited.capture_limit_bytes = 1024;
        std::size_t streamed = 0;
        const auto output = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--output"}, L"", {},
            [&](const std::string& text) { streamed += text.size(); }, nullptr, limited);
        Require(output.output_truncated && !output.success && output.std_out.size() == 1024 && streamed == 1024 * 1024,
            "Bounded capture lost streaming bytes or hid truncation");
        const auto callback = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--output"}, L"", {},
            [](const std::string&) { throw std::runtime_error("controlled consumer failure"); });
        Require(callback.callback_failed && !callback.success, "Output callback failure escaped or reported success");
        journal->Flush();
        std::ifstream events(journal->Directory() / "events.jsonl");
        std::string line; bool cancelled = false, deadline = false;
        while (std::getline(events, line)) {
            const auto value = JsonValue::Parse(line); const auto data = value ? value->Get("data") : nullptr;
            if (data) {
                cancelled |= data->GetString("exit_kind") == "cancelled" && data->GetString("state") == "cancelled";
                deadline |= data->GetString("exit_kind") == "deadline";
            }
        }
        Require(cancelled && deadline, "Journal lost cancellation/deadline terminal states");
        std::cout << "Process ownership, cancel/deadline, nested jobs and bounded output: PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
