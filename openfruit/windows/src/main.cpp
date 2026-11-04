#include "cli_commands.hpp"
#include "console_cancellation.hpp"
#include "event_journal.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"
#include <windows.h>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace OpenFruit;

static LONG WINAPI OpenFruitCrashFilter(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void* addr = ep->ExceptionRecord->ExceptionAddress;
    std::cerr << "OPENFRUIT FATAL EXCEPTION: 0x" << std::hex << code
              << " at address " << addr << std::dec << "\n";
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        std::cerr << "  Access violation "
                  << (ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "READING" :
                      ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "WRITING" : "EXECUTING")
                  << " address 0x" << std::hex << ep->ExceptionRecord->ExceptionInformation[1] << std::dec << "\n";
    }
    HMODULE hMod = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &hMod)) {
        char modName[MAX_PATH] = {0};
        GetModuleFileNameA(hMod, modName, sizeof(modName));
        std::cerr << "  Crashing module: " << modName << " base: 0x" << std::hex << (uintptr_t)hMod
                  << " offset: 0x" << ((uintptr_t)addr - (uintptr_t)hMod) << std::dec << "\n";
    }
    void* stack[32];
    USHORT frames = CaptureStackBackTrace(0, 32, stack, NULL);
    for (USHORT i = 0; i < frames; ++i) {
        HMODULE frameMod = NULL;
        char frameModName[MAX_PATH] = "unknown";
        uintptr_t frameOffset = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)stack[i], &frameMod)) {
            GetModuleFileNameA(frameMod, frameModName, sizeof(frameModName));
            frameOffset = (uintptr_t)stack[i] - (uintptr_t)frameMod;
        }
        std::cerr << "  #" << i << " " << stack[i] << " (" << frameModName << " + 0x" << std::hex << frameOffset << std::dec << ")\n";
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char* argv[]) {
    SetUnhandledExceptionFilter(OpenFruitCrashFilter);
    bool json = false;
    bool protocol_stdio = false;
    std::vector<char*> arguments;
    arguments.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--diagnostics=json" || argument == "--json-diagnostics") json = true;
        else {
            if (argument == "--protocol-stdio") protocol_stdio = true;
            arguments.push_back(argv[i]);
        }
    }
    if (json && protocol_stdio) {
        std::cerr << "--protocol-stdio cannot be combined with JSON stdout diagnostics\n";
        return 2;
    }
    arguments.push_back(nullptr);

    // Legacy domain console writes go to the human channel until those domains
    // have migrated to event-only rendering. Preserve stdout exclusively for
    // the machine sink, including on exceptions and early command returns.
    struct HumanChannel {
        std::streambuf* original;
        bool redirected;
        explicit HumanChannel(bool enabled) : original(std::cout.rdbuf()), redirected(enabled) {
            if (redirected) std::cout.rdbuf(std::cerr.rdbuf());
        }
        ~HumanChannel() { if (redirected) std::cout.rdbuf(original); }
    } human(json);
    std::ostream machine(human.original);
    try {
        std::shared_ptr<EventJournal> journal;
        try {
            journal = EventJournal::AttachFromEnvironment();
            if (!journal) journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "build-events");
        } catch (const std::exception& error) {
            if (json) throw;
            std::cerr << "OPENFRUIT journal unavailable: " << error.what() << '\n';
        }
        auto context = journal ? std::make_shared<OperationContext>(*journal->Context()) : std::make_shared<OperationContext>();
        if (json) {
            auto stream = std::make_shared<JsonStreamSink>(machine);
            context->sink = std::make_shared<CompositeEventSink>(
                std::vector<std::shared_ptr<EventSink>>{journal->Context()->sink, stream});
        }
        OperationBinding binding(context);
        ConsoleCancellation cancellation(context);
        auto metadata = JsonValue::ObjectValue();
        metadata.Set("command", JsonValue::String(arguments.size() > 2 ? arguments[1] : "help"));
        if (journal) metadata.Set("journal_directory", JsonValue::String(journal->Directory().string()));
        OperationSpan command("cli.command", std::move(metadata));
        const int command_exit = RunCommand(static_cast<int>(arguments.size() - 1), arguments.data(), journal);
        cancellation.Finish(); // Drain the cancelling event before command terminal/flush.
        const int exit = context->CancellationRequested() ? 130 : command_exit;
        auto result = JsonValue::ObjectValue();
        result.Set("exit_code", JsonValue::Number(std::to_string(exit)));
        command.Complete(std::move(result), context->CancellationRequested() ? OperationOutcome::Cancelled :
            exit == 0 ? OperationOutcome::Succeeded : OperationOutcome::Failed);
        if (journal) {
            journal->Flush();
            if (journal->HasErrors()) context->Emit("journal.error", JsonValue::ObjectValue(), "error");
        }
        return exit;
    } catch (const std::exception& error) {
        std::cerr << "OPENFRUIT diagnostics initialization failed: " << error.what() << '\n';
        return 1;
    }
}
