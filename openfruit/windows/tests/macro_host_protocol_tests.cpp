#include "json_value.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"
#include "../../../native/macro-host/transport.hpp"
#include "../../../native/macro-host/budget.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstring>
using namespace OpenFruit;
namespace fs = std::filesystem;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
};
void Require(bool value, const char* error) { if (!value) throw std::runtime_error(error); }
std::string Read(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}
std::string Frame(const std::string& json) {
    const std::uint64_t size = json.size();
    return std::string(reinterpret_cast<const char*>(&size), sizeof(size)) + json;
}
struct Reply { DWORD exit; std::vector<JsonValue> frames; };
Reply Exchange(const fs::path& host, const fs::path& root, const std::string& bytes) {
    { std::ofstream in(root / "input", std::ios::binary); in.write(bytes.data(), bytes.size()); }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle input{CreateFileW((root / "input").c_str(), GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, 0, nullptr)};
    Handle output{CreateFileW((root / "output").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, 0, nullptr)};
    Handle error{CreateFileW((root / "error").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, 0, nullptr)};
    Handle job{CreateJobObjectW(nullptr, nullptr)};
    Require(input.value != INVALID_HANDLE_VALUE && output.value != INVALID_HANDLE_VALUE && error.value != INVALID_HANDLE_VALUE && job.value, "protocol handles failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limit, sizeof(limit)), "protocol job limit failed");
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.value; startup.hStdOutput = output.value; startup.hStdError = error.value;
    PROCESS_INFORMATION proc{};
    auto command = Win32Process::QuoteArgument(host.wstring());
    Require(CreateProcessW(host.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, root.c_str(), &startup, &proc), "host launch failed");
    Handle process{proc.hProcess}, thread{proc.hThread};
    if (!AssignProcessToJobObject(job.value, process.value)) {
        TerminateProcess(process.value, 2); throw std::runtime_error("host job assignment failed");
    }
    Require(ResumeThread(thread.value) != DWORD(-1), "host resume failed");
    Require(WaitForSingleObject(process.value, 5000) == WAIT_OBJECT_0, "host protocol timed out");
    DWORD exit = 0; Require(GetExitCodeProcess(process.value, &exit), "host exit missing");
    const auto raw = Read(root / "output");
    Reply result{exit, {}};
    std::size_t offset = 0;
    while (offset < raw.size()) {
        Require(raw.size() - offset >= 8, "truncated output header");
        std::uint64_t size = 0; std::memcpy(&size, raw.data() + offset, 8); offset += 8;
        Require(size && size <= raw.size() - offset, "truncated output body");
        const auto json = JsonValue::Parse(raw.substr(offset, size));
        Require(json.has_value(), "invalid output JSON");
        result.frames.push_back(*json); offset += size;
    }
    return result;
}

void TransportContracts(const fs::path& root) {
    using namespace OpenFruit::MacroHost;
    const std::map<std::string, std::string> modules{{"OwnedModule", "/original/libOwnedModule.dylib"}};
    const PathTranslator translate = [](const std::string& requested, std::string& target) {
        if (requested != "C:\\owned\\libOwnedModule.dylib") return false;
        target = "/original/libOwnedModule.dylib"; return true;
    };
    std::map<std::string, std::string> selected;
    std::vector<std::string> selected_plugins;
    Require(SelectModules("OwnedModule", modules, selected, selected_plugins) && selected == modules && selected_plugins.size() == 1,
            "generic module selection failed");
    for (const auto* invalid : {"", "OtherModule", "OwnedModule,", ",OwnedModule", "OwnedModule,OwnedModule"})
        Require(!SelectModules(invalid, modules, selected, selected_plugins) && selected.empty() && selected_plugins.empty(),
                "invalid module subset was retained or admitted");
    std::string projected, error;
    const std::string ordinary = " { \"futureRequest\" : {\"text\":\"loadPluginLibrary\"} } ";
    Require(ProjectRequest(ordinary, modules, translate, projected, error) && projected == ordinary,
            "ordinary protocol bytes changed");
    const auto loading = R"({"loadPluginLibrary":{"moduleName":"OwnedModule","libraryPath":"C:\\owned\\libOwnedModule.dylib","extension":{"extra":17}}})";
    Require(ProjectRequest(loading, modules, translate, projected, error), "admitted path projection failed");
    const auto mapped = JsonValue::Parse(projected);
    Require(mapped && mapped->Get("loadPluginLibrary")->GetString("libraryPath") == modules.at("OwnedModule") &&
            mapped->Get("loadPluginLibrary")->Get("extension")->Get("extra")->Int() == 17,
            "projection changed non-path data");
    for (const auto& invalid : {std::string("not JSON"), std::string(R"({"loadPluginLibrary":{"moduleName":"OtherModule","libraryPath":"C:\\owned\\libOwnedModule.dylib"}})"),
            std::string(R"({"loadPluginLibrary":{"moduleName":"OwnedModule","libraryPath":"C:\\outside\\libOwnedModule.dylib"}})"),
            std::string(R"({"loadPluginLibrary":{"moduleName":"OwnedModule","libraryPath":42}})")})
        Require(!ProjectRequest(invalid, modules, translate, projected, error) && !error.empty(), "unadmitted protocol input accepted");
    const auto open_input = [&](HANDLE& reader, HANDLE& writer) { Require(CreatePipe(&reader, &writer, nullptr, 0), "owned input pipe failed"); };
    HANDLE reader = nullptr, writer = nullptr;
    open_input(reader, writer);
    {
        OpenFruit::MacroHost::Handle in(reader), kept_writer(writer);
        const auto started = GetTickCount64();
        const auto stopped = RunSession(reader, modules, translate, [](HANDLE, CancellationToken) { return 7; });
        Require(stopped.runtime_exit == 7 && !stopped.broker_failed && GetTickCount64() - started < 2000,
                "runtime completion did not interrupt blocked compiler input");
        DWORD flags = 0; Require(GetHandleInformation(reader, &flags), "borrowed compiler stdin was closed");
    }
    // Zero terminates transport and trailing bytes are never admitted to guest.
    const auto input_file = root / "transport-zero-input";
    { std::ofstream file(input_file, std::ios::binary); file << std::string(8, '\0') << "trailing"; }
    {
        OpenFruit::MacroHost::Handle input(CreateFileW(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        const auto stopped = RunSession(input.value, modules, translate, [](HANDLE input, CancellationToken) {
            char byte = 0; DWORD received = 0;
            return !ReadFile(input, &byte, 1, &received, nullptr) && GetLastError() == ERROR_BROKEN_PIPE ? 0 : 8;
        });
        Require(stopped.runtime_exit == 0 && !stopped.broker_failed, "zero termination did not produce genuine guest EOF");
    }
    // A partial frame cancels a live backend rather than pretending EOF/success.
    open_input(reader, writer);
    {
        OpenFruit::MacroHost::Handle input(reader), sender(writer);
        Require(WriteExact(writer, "bad", 3), "partial input write failed"); sender.Reset();
        const auto stopped = RunSession(reader, modules, translate, [](HANDLE input, CancellationToken token) {
            char byte = 0; DWORD received = 0; ReadFile(input, &byte, 1, &received, nullptr);
            while (!token.Requested()) Sleep(1);
            return 9;
        });
        Require(stopped.broker_failed && stopped.runtime_exit == 9, "malformed request did not cancel original session");
    }
    // Cancellation must break broker writes when the private input pipe is full.
    const auto large_input = root / "transport-large-input";
    { std::ofstream file(large_input, std::ios::binary); const auto data = Frame("{\"owned\":{\"text\":\"" + std::string(1024 * 1024, 'x') + "\"}}"); file.write(data.data(), data.size()); }
    {
        OpenFruit::MacroHost::Handle input(CreateFileW(large_input.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        const auto started = GetTickCount64();
        std::atomic<bool> input_backpressure{false};
        const auto stopped = RunSession(input.value, modules, translate, [&](HANDLE guest_input, CancellationToken token) {
            while (!token.Requested()) {
                DWORD available = 0;
                if (PeekNamedPipe(guest_input, nullptr, 0, nullptr, &available, nullptr) && available) input_backpressure.store(true);
                Sleep(1);
            }
            return 0;
        }, [&] { return input_backpressure.load() || GetTickCount64() - started >= 1000; });
        Require(stopped.cancelled && input_backpressure.load() && GetTickCount64() - started < 2000,
                "backpressured broker cancellation deadlocked or failed to exercise a full pipe");
    }
    // Cancellation also breaks a runtime worker synchronously blocked on output.
    HANDLE output_reader = nullptr, output_writer = nullptr;
    open_input(reader, writer); open_input(output_reader, output_writer);
    {
        OpenFruit::MacroHost::Handle input(reader), sender(writer), held_output(output_reader), blocked_output(output_writer);
        const auto started = GetTickCount64();
        std::atomic<bool> output_backpressure{false}, write_succeeded{false};
        std::atomic<DWORD> write_error{ERROR_SUCCESS};
        const auto stopped = RunSession(reader, modules, translate, [&](HANDLE, CancellationToken) {
            const std::string bytes(1024 * 1024, 'z');
            const bool written = WriteExact(output_writer, bytes.data(), bytes.size());
            const auto error = written ? ERROR_SUCCESS : GetLastError();
            write_succeeded.store(written); write_error.store(error); return 0;
        }, [&] {
            DWORD available = 0;
            if (PeekNamedPipe(output_reader, nullptr, 0, nullptr, &available, nullptr) && available)
                output_backpressure.store(true);
            return output_backpressure.load() || GetTickCount64() - started >= 1000;
        });
        DWORD buffered = 0;
        const bool peek_after = PeekNamedPipe(output_reader, nullptr, 0, nullptr, &buffered, nullptr) != FALSE;
        const DWORD peek_error = peek_after ? ERROR_SUCCESS : GetLastError();
        const auto elapsed = GetTickCount64() - started;
        // A cancelled native write may withdraw its pending bytes. Backpressure
        // must therefore be observed before cancellation, and cancellation itself
        // is proved by the actual blocked worker's ERROR_OPERATION_ABORTED.
        const std::string predicates = "pre_backpressure=" + std::to_string(output_backpressure.load()) +
            ", write_succeeded=" + std::to_string(write_succeeded.load()) + ", write_error=" + std::to_string(write_error.load()) +
            ", post_peek=" + std::to_string(peek_after) + ", post_buffered=" + std::to_string(buffered) +
            ", post_peek_error=" + std::to_string(peek_error) + ", cancelled=" + std::to_string(stopped.cancelled) +
            ", elapsed_ms=" + std::to_string(elapsed);
        std::cout << "Output cancellation predicates: " << predicates << '\n';
        if (!output_backpressure.load() || write_succeeded.load() || write_error.load() != ERROR_OPERATION_ABORTED ||
            !stopped.cancelled || elapsed >= 2000)
            throw std::runtime_error("blocked runtime output cancellation contract failed: " + predicates);
    }
}

int OwnedBudgetHolder(const std::string& name, const std::wstring& event_name) {
    OpenFruit::MacroHost::Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name.c_str()));
    OpenFruit::MacroHost::SessionBudget budget;
    if (!ready.value || budget.Acquire(name) != OpenFruit::MacroHost::BudgetStatus::Acquired) return 2;
    SetEvent(ready.value);
    // Parent owns this real process through a kill-on-close job. Deliberate
    // abrupt termination tests Windows abandoned-owner recovery, not emulation.
    Sleep(INFINITE);
    return 3;
}
void BudgetContracts(const fs::path& self, const fs::path& root) {
    using OpenFruit::MacroHost::SessionBudget;
    using OpenFruit::MacroHost::BudgetStatus;
    const auto name = OpenFruit::MacroHost::BudgetNamespace(root);
    Require(name && OpenFruit::MacroHost::BudgetNamespace(root / ".") == name, "managed root budget namespace aliases differ");
    const auto other = root / "different-managed-root"; fs::create_directory(other);
    Require(OpenFruit::MacroHost::BudgetNamespace(other) != name, "different managed roots share a pool");
    OpenFruit::MacroHost::Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{}; limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Require(job.value && SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limit, sizeof(limit)), "owned budget job failed");
    struct Child { OpenFruit::MacroHost::Handle process, thread, ready; };
    std::unique_ptr<Child> children[2];
    for (unsigned index = 0; index < 2; ++index) {
        children[index] = std::make_unique<Child>(); auto& child = *children[index];
        const auto event_name = L"Local\\OPENFRUITOwnedBudget-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(index);
        child.ready.value = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());
        Require(child.ready.value != nullptr, "budget readiness event failed");
        auto command = Win32Process::BuildCommandLine({self.wstring(), L"--owned-budget-holder", Win32Process::ToWide(*name), event_name});
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
        Require(CreateProcessW(self.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                               nullptr, root.c_str(), &startup, &process), "owned budget process launch failed");
        child.process.value = process.hProcess; child.thread.value = process.hThread;
        if (!AssignProcessToJobObject(job.value, process.hProcess)) { TerminateProcess(process.hProcess, 2); throw std::runtime_error("owned budget job assignment failed"); }
        Require(ResumeThread(process.hThread) != DWORD(-1) && WaitForSingleObject(child.ready.value, 5000) == WAIT_OBJECT_0,
                "two owned processes did not acquire separate budget slots");
    }
    SessionBudget waiting;
    const auto started = GetTickCount64();
    Require(waiting.Acquire(*name, [&] { return GetTickCount64() - started >= 80; }) == BudgetStatus::Cancelled,
            "third cross-process session escaped fixed two-slot budget");
    HANDLE reader = nullptr, writer = nullptr;
    Require(CreatePipe(&reader, &writer, nullptr, 0), "queued EOF pipe failed");
    {
        OpenFruit::MacroHost::Handle input(reader), sender(writer); sender.Reset();
        SessionBudget empty_client;
        Require(empty_client.Acquire(*name, {}, reader) == BudgetStatus::InputClosed, "queued closed compiler input was ignored");
    }
    Require(TerminateProcess(children[0]->process.value, 57) && WaitForSingleObject(children[0]->process.value, 5000) == WAIT_OBJECT_0,
            "owned budget process termination failed");
    // waiting retains handles across the owner death, making WAIT_ABANDONED
    // observable rather than allowing the last handle to destroy the mutex.
    SessionBudget recovered;
    Require(recovered.Acquire(*name) == BudgetStatus::Acquired && recovered.AbandonedOwnerRecovered(),
            "terminated process permanently lost its budget slot");
    Require(recovered.Release(), "budget was not released by its owning thread");
    SessionBudget reuse;
    Require(reuse.Acquire(*name) == BudgetStatus::Acquired && !reuse.AbandonedOwnerRecovered() && reuse.Release(),
            "normal budget release did not admit another session");
    Require(TerminateProcess(children[1]->process.value, 58) && WaitForSingleObject(children[1]->process.value, 5000) == WAIT_OBJECT_0,
            "second owned budget process termination failed");
}
int main(int argc, char** argv) {
    fs::path root;
    try {
        if (argc == 4 && std::string(argv[1]) == "--owned-budget-holder")
            return OwnedBudgetHolder(argv[2], Win32Process::ToWide(argv[3]));
        Require(argc == 2, "expected host path");
        root = fs::temp_directory_path() / ("OPENFRUIT-macro-protocol-" + NewOperationId());
        fs::create_directories(root);
        const auto host = fs::absolute(argv[1]);
        TransportContracts(root);
        wchar_t own_path[32768]{};
        Require(GetModuleFileNameW(nullptr, own_path, 32768) != 0, "budget test executable path missing");
        BudgetContracts(own_path, root);
        // Configured failures must not fall back to the unsupported capability
        // responder, which could hide corrupt managed provider publication.
        ProcessRunOptions invalid_options;
        invalid_options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        const auto invalid_provider = Win32Process::Run(host.wstring(), {host.wstring()}, root.wstring(),
            {{L"OPENFRUIT_DARWIN_MACRO_PROVIDER", (root / "missing-provider.json").wstring()},
             {L"OPENFRUIT_DARWIN_MACRO_MODULES", L"OwnedModule"}}, nullptr, nullptr, invalid_options);
        Require(invalid_provider.launched && !invalid_provider.timed_out && invalid_provider.exit_code != 0 &&
                invalid_provider.std_out.empty() && invalid_provider.std_err.find("Invalid managed macro provider") != std::string::npos,
                "configured provider failure silently fell back or polluted stdout");
        // Real host transport, with no replacement plugin or generated expansion.
        const auto reply = Exchange(host, root,
            Frame(R"({"getCapability":{"capability":{"protocolVersion":7}}})") +
            Frame(R"({"loadPluginLibrary":{"libraryPath":"C:\\Windows\\System32\\kernel32.dll","moduleName":"owned-test"}})") +
            Frame(R"({"expandFreestandingMacro":{"syntax":{"source":"\"getCapability\""}}})") +
            Frame(R"({"expandAttachedMacro":{"attributeSyntax":{"source":"\"loadPluginLibrary\""}}})"));
        Require(reply.exit == 0 && reply.frames.size() == 4, "valid requests lost responses");
        const auto* cap = reply.frames[0].Get("getCapabilityResult");
        Require(cap && cap->Get("capability"), "capability absent");
        const auto* features = cap->Get("capability")->Get("features");
        Require(features && features->IsArray() && features->ArrayItems().empty(), "unsupported loader advertised");
        for (std::size_t i = 1; i < 4; ++i) {
            const char* expectedKey = (i == 1) ? "loadPluginLibraryResult" : ((i == 2) ? "expandFreestandingMacroResult" : "expandAttachedMacroResult");
            const auto* payload = reply.frames[i].Get(expectedKey);
            Require(payload, "wrong response variant (nested strings routed request)");
            if (i == 1) Require(payload->Get("loaded") && !payload->Get("loaded")->Bool(), "unexecutable library reported loaded");
            else if (i == 2) Require(!payload->Get("expandedSource") || payload->Get("expandedSource")->IsNull(), "placeholder expansion returned");
            else Require(!payload->Get("expandedSources") || payload->Get("expandedSources")->IsNull(), "placeholder expansion returned");
            const auto* diagnostics = payload->Get("diagnostics");
            Require(diagnostics && diagnostics->ArrayItems().size() == 1, "unsupported operation lacks diagnostic");
            const auto& d = diagnostics->ArrayItems()[0];
            Require(d.GetString("severity") == "error" && !d.GetString("message").empty() && d.Get("position") && d.Get("highlights") && d.Get("notes") && d.Get("fixIts"), "diagnostic does not match Swift protocol");
        }
        // The actual unmodified local Apple images are optional integration
        // inputs. Presence is never inferred to mean runtime execution works.
        std::size_t original_images = 0;
        std::error_code scan_error;
        const auto plugins = ToolPaths::DarlingRoot({}) / "windows-plugin-view";
        const bool original_directory = fs::is_directory(plugins, scan_error);
        if (!original_directory && scan_error == std::errc::no_such_file_or_directory) scan_error.clear();
        if (original_directory) {
            for (fs::directory_iterator file(plugins, scan_error), end; !scan_error && file != end; file.increment(scan_error)) {
                if (!file->is_regular_file(scan_error) || file->is_symlink(scan_error)) continue;
                auto payload = JsonValue::ObjectValue(), request = JsonValue::ObjectValue();
                payload.Set("libraryPath", JsonValue::String(file->path().string()));
                payload.Set("moduleName", JsonValue::String("original integration input"));
                request.Set("loadPluginLibrary", std::move(payload));
                const auto original = Exchange(host, root, Frame(request.Serialize()));
                Require(original.exit == 0 && original.frames.size() == 1, "original-image preflight lost response");
                const auto* loaded = original.frames[0].Get("loadPluginLibraryResult");
                Require(loaded && !loaded->Get("loaded")->Bool(), "metadata inspection claimed plugin execution");
                const auto text = loaded->Get("diagnostics")->ArrayItems()[0].GetString("message");
                Require(text.find("Mach-O host slice") != std::string::npos && text.find("backend is not configured") != std::string::npos,
                    "actual Apple Mach-O image was not inspected through the host");
                ++original_images;
            }
        }
        Require(!scan_error, "original image inventory failed");
        std::cout << "Original Apple images preflighted (no execution): " << original_images << '\n';
        std::uint64_t huge = 16ull * 1024 * 1024 + 1;
        for (const auto& bad : {Frame("not JSON"), Frame(R"({"unknown":{}})"), Frame(R"({"getCapability":{},"loadPluginLibrary":{}})"), std::string(3, '\0'), std::string(7, '\0'), Frame("{} ").substr(0, 9), std::string(reinterpret_cast<const char*>(&huge), 8)}) {
            const auto rejected = Exchange(host, root, bad);
            Require(rejected.exit != 0 && rejected.frames.empty(), "invalid request accepted or fake response produced");
        }
        Require(Exchange(host, root, "").exit == 0, "clean EOF reported failure");
        const auto termination = Exchange(host, root, std::string(8, '\0'));
        Require(termination.exit == 0 && termination.frames.empty(), "protocol termination reported malformed input");
        const auto terminated_session = Exchange(host, root,
            Frame(R"({"getCapability":{"capability":{"protocolVersion":8}}})") +
            std::string(8, '\0') + Frame("not JSON"));
        Require(terminated_session.exit == 0 && terminated_session.frames.size() == 1,
            "protocol termination did not end a live session without another response");
        const auto swiftc = ToolPaths::SwiftBin({}) / "swiftc.exe";
        Require(fs::is_regular_file(swiftc), "real Swift consumer unavailable");
        const auto source = root / "consumer.swift";
        {
            std::ofstream file(source);
            file << "@freestanding(declaration) macro ownedUnavailable() = #externalMacro(module: \"OwnedTestMacro\", type: \"UnavailableMacro\")\n"
                 << "#ownedUnavailable()\n";
        }
        ProcessRunOptions options;
        options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        const auto consumer = Win32Process::Run(swiftc.wstring(), {
            // Declaration-only protocol consumer needs no standard-library SDK.
            // This does not validate or override the application's SDK selection.
            swiftc.wstring(), L"-typecheck", L"-parse-stdlib", source.wstring(), L"-load-plugin-executable",
            host.wstring() + L"#OwnedTestMacro"
        }, root.wstring(), {}, nullptr, nullptr, options);
        Require(consumer.launched && !consumer.timed_out && consumer.exit_code != 0 &&
            consumer.std_err.find("native macro execution is unavailable") != std::string::npos &&
            consumer.std_err.find("malformed") == std::string::npos,
            "real Swift did not consume unsupported-execution diagnostic");
        fs::remove_all(root);
        std::cout << "PASS: real macro host rejects unsupported execution and malformed transport\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FAIL: " << ex.what() << "\n";
        return 1;
    }
}
