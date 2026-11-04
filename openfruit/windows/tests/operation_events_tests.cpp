#include "event_journal.hpp"
#include "process_diagnostics.hpp"
#include "win32_process.hpp"

#include <atomic>
#include <fstream>
#include <iostream>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class Collector final : public EventSink {
public:
    std::vector<OperationEvent> events;
    void Emit(OperationEvent event) noexcept override {
        std::lock_guard lock(mutex_);
        events.push_back(std::move(event));
    }
private:
    std::mutex mutex_;
};

std::vector<JsonValue> ReadEvents(const fs::path& directory) {
    std::ifstream input(directory / "events.jsonl", std::ios::binary);
    Require(static_cast<bool>(input), "Journal was not created");
    std::vector<JsonValue> result;
    std::string line;
    while (std::getline(input, line)) {
        auto value = JsonValue::Parse(line);
        Require(value.has_value(), "Journal contains invalid JSON");
        result.push_back(std::move(*value));
    }
    return result;
}

void TestDiagnosticsAndProgress() {
    {
        std::ostringstream output;
        auto stream = std::make_shared<JsonStreamSink>(output);
        auto collector = std::make_shared<Collector>();
        CompositeEventSink sinks({stream, collector});
        auto data = JsonValue::ObjectValue();
        auto nested = JsonValue::ArrayValue();
        nested.ArrayItems().push_back(JsonValue::String("https://user:owned-credential@example.org/?token=owned-token"));
        data.Set("nested", std::move(nested));
        sinks.Emit({"test.composite", "info", "build", "span", "", std::move(data)});
        const auto record = JsonValue::Parse(output.str());
        Require(record.has_value() && collector->events.size() == 1, "Composite sink lost an event");
        Require(output.str().find("owned-credential") == std::string::npos &&
                output.str().find("owned-token") == std::string::npos, "Machine stream exposed a credential");
    }
    auto sink = std::make_shared<Collector>();
    auto context = std::make_shared<OperationContext>(OperationContext{sink, NewOperationId(), NewOperationId(), {}});
    OperationBinding binding(context);
    ProcessDiagnostics parser(context, L"C:/workspace", {"synthetic-password.swift"});
    const std::string diagnostic = "Sources/caf\xc3\xa9.swift:12:7: error: synthetic-password.swift is invalid\r\n"
                                   "Sources/caf\xc3\xa9.swift:13:2: note: declaration here\n";
    for (char byte : diagnostic) parser.Feed(std::string(1, byte));
    parser.Finish();
    Require(sink->events.size() == 2, "Chunked diagnostics were lost or duplicated");
    const auto& error = sink->events[0].data;
    Require(error.Get("line")->Int() == 12 && error.Get("column")->Int() == 7, "Source navigation is wrong");
    Require(error.GetString("file").find("caf\xc3\xa9.swift") != std::string::npos, "UTF-8 source path was corrupted");
    Require(error.GetString("message").find("synthetic-password.swift") == std::string::npos, "Diagnostic exposed a known secret");
    Require(sink->events[1].data.GetString("related_diagnostic_id") == error.GetString("diagnostic_id"), "Related note lost its diagnostic");
    {
        OperationSpan task("test.task");
        Require(CurrentOperationContext()->span_id != context->span_id, "Task context was not attached");
        task.Complete(JsonValue::ObjectValue(), true);
        Require(CurrentOperationContext() == context, "Completed task leaked its context");
    }
    {
        StageProgress progress({"compile", "package"});
        progress.Started("compile");
        progress.Completed("compile");
        progress.Completed("compile");
        progress.Finished(false);
    }
    const auto& snapshot = sink->events.back().data;
    Require(snapshot.GetString("state") == "failed" && snapshot.Get("percent")->Int() == 50,
            "Failed build reported success or double-counted work");
    {
        StageProgress incomplete({"compile", "package"});
        incomplete.Completed("compile");
        incomplete.Finished(true);
    }
    Require(sink->events.back().data.GetString("state") == "failed", "Incomplete plan reached 100% success");

    const auto command = DescribeCommand(L"zsign.exe", {L"zsign.exe", L"-p", L"synthetic-password.swift"}, L"").Serialize();
    Require(command.find("synthetic-password.swift") == std::string::npos, "Source-like password escaped argument redaction");
    const auto shell = DescribeCommand(L"cmd.exe", {L"cmd.exe", L"/c", L"echo synthetic-secret"}, L"").Serialize();
    Require(shell.find("synthetic-secret") == std::string::npos, "Shell body entered the journal");
    const auto url = RedactDiagnosticText("https://user:synthetic-token@example.org/file?token=another-token");
    Require(url.find("synthetic-token") == std::string::npos && url.find("another-token") == std::string::npos,
            "Authenticated URL was not redacted");
}

void TestToolStackDiagnostics() {
    auto sink = std::make_shared<Collector>();
    auto context = std::make_shared<OperationContext>(OperationContext{sink, NewOperationId(), NewOperationId(), {}});
    ProcessDiagnostics parser(context, L"C:/workspace", {"owned-sensitive-value"});
    const std::string output = "C:\\SDK Tools\\llvm-ar.exe: error: archive damaged\n"
        "Stack dump:\n0. Program arguments: --token owned-sensitive-value error: do not record command\n"
        "Exception Code: 0xC0000005\n"
        " #0 0x00007ff612345678 (C:\\SDK Tools\\ld64.lld.exe+0xa19324)\n"
        "#1 0x00007ff612345679 OwnedFunction (C:\\SDK Tools\\ld64.lld.exe+0xa19325)\n";
    for (const char byte : output) parser.Feed(std::string(1, byte));
    parser.Finish();
    bool tool_error = false, frame = false;
    for (const auto& event : sink->events) {
        Require(event.data.Serialize().find("owned-sensitive-value") == std::string::npos, "Stack metadata exposed credentials");
        Require(event.data.Serialize().find("do not record command") == std::string::npos, "Stack preamble became a diagnostic");
        if (event.kind == "diagnostic" && event.data.GetString("message") == "archive damaged") tool_error = true;
        if (event.kind == "diagnostic.stack_frame" && event.data.GetString("module_offset") == "0xa19324") frame = true;
    }
    Require(tool_error, "Windows tool path hid the causal diagnostic");
    Require(frame, "Tool stack frames were discarded");
    Require(parser.StackFrameCount() == 2, "Stack frame count is inaccurate");
    ProcessDiagnostics bounded(context, L"");
    bounded.Feed("Stack dump:\n");
    for (int index = 0; index < 300; ++index)
        bounded.Feed("#" + std::to_string(index) + " 0x1234 (C:\\OwnedFixture\\tool.exe+0x1234)\n");
    bounded.Finish();
    Require(bounded.StackFrameCount() == 256, "Unbounded stack metadata");
    int truncations = 0;
    for (const auto& event : sink->events) if (event.kind == "diagnostic.stack_truncated") ++truncations;
    Require(truncations == 1, "Stack truncation was hidden or duplicated");
}

int Child(const std::string& mode) {
    auto journal = EventJournal::AttachFromEnvironment();
    Require(static_cast<bool>(journal), "Process runner did not propagate the journal context");
    OperationBinding binding(journal->Context());
    if (mode == "crash" || mode == "stack-crash") {
        if (mode == "stack-crash") {
            std::cerr << "Stack dump:\nException Code: 0xC0000005\n"
                         "#0 0x0000000012345678 (C:\\OwnedFixture\\tool.exe+0x1234)\n";
            std::cerr.flush();
        }
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        SetUnhandledExceptionFilter([](EXCEPTION_POINTERS*) -> LONG { return EXCEPTION_EXECUTE_HANDLER; });
        RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
        return 99;
    }
    if (mode == "diagnostic") {
        std::cerr << "C:/workspace/Probe.swift:9:4: error: controlled compiler diagnostic\n";
        return 7;
    }
    OperationSpan task("child.events");
    for (int index = 0; index < 100; ++index) {
        auto data = JsonValue::ObjectValue();
        data.Set("index", JsonValue::Number(std::to_string(index)));
        CurrentOperationContext()->Emit("test.child.event", std::move(data));
    }
    task.Succeed();
    return 0;
}

void TestProductionProcessPath(const fs::path& executable, const fs::path& root) {
    auto journal = EventJournal::Create(root);
    OperationBinding binding(journal->Context());
    const auto error = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--child", L"diagnostic"});
    Require(error.launched && error.exit_code == 7 && !error.success, "Tool failure changed process semantics");
    Require(error.std_err.find("controlled compiler diagnostic") != std::string::npos, "Original compiler diagnostic was lost");
    const auto launch = Win32Process::Run((root / "does-not-exist.exe").wstring(), {(root / "does-not-exist.exe").wstring()});
    Require(!launch.launched && launch.win32_error != 0, "Launch failure lost its Windows error");
    const auto crash = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--child", L"crash"});
    Require(crash.launched && static_cast<unsigned long>(crash.exit_code) == EXCEPTION_ACCESS_VIOLATION,
            "Native crash was not preserved");
    const auto stack_crash = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--child", L"stack-crash"});
    Require(static_cast<unsigned long>(stack_crash.exit_code) == EXCEPTION_ACCESS_VIOLATION
        && stack_crash.tool_stack_frame_count == 1, "Original runner lost tool-reported crash frames");
    const auto context = CurrentOperationContext();
    std::atomic<bool> child_failed{false};
    std::vector<std::thread> threads;
    for (int worker = 0; worker < 3; ++worker) {
        threads.emplace_back([&, context] {
            OperationBinding worker_binding(context);
            const auto child = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--child", L"events"});
            if (!child.success) child_failed = true;
        });
    }
    for (auto& thread : threads) thread.join();
    Require(!child_failed.load(), "Concurrent child journal writer failed");
    journal->Flush();
    Require(!journal->HasErrors(), "Journal lost normal build events");
    const auto events = ReadEvents(journal->Directory());
    std::uint64_t previous = 0;
    int child_count = 0;
    bool diagnostic = false, observed_crash = false, observed_stack = false, observed_launch = false;
    for (const auto& event : events) {
        const auto sequence = std::stoull(event.Get("sequence")->Serialize());
        Require(sequence == previous + 1, "Cross-process event sequence contains a gap or duplicate");
        previous = sequence;
        Require(event.GetString("build_id") == context->build_id, "Child event escaped its originating build");
        const auto* data = event.Get("data");
        if (event.GetString("kind") == "test.child.event") ++child_count;
        if (event.GetString("kind") == "diagnostic" && data->Get("line") && data->Get("line")->Int() == 9) diagnostic = true;
        if (data->GetString("exit_kind") == "native_exception_exit") {
            if (data->GetString("stack_trace_status") == "unavailable") observed_crash = true;
            if (data->GetString("stack_trace_status") == "tool_output") observed_stack = true;
        }
        if (data->GetString("exit_kind") == "launch_failed") observed_launch = true;
    }
    Require(child_count == 300 && diagnostic && observed_crash && observed_stack && observed_launch, "Original process path did not produce required structured events");
    std::ostringstream replay;
    std::string replay_error;
    Require(EventJournal::Replay(journal->Directory(), 5, 7, replay, replay_error), "Cursor replay failed");
    int replayed = 0;
    std::istringstream replay_lines(replay.str());
    std::string line;
    while (std::getline(replay_lines, line)) {
        const auto event = JsonValue::Parse(line);
        Require(std::stoull(event->Get("sequence")->Serialize()) > 5, "Replay ignored its cursor");
        ++replayed;
    }
    Require(replayed == 7, "Replay ignored its page limit");
}

void TestJournalLossAndIsolation(const fs::path& root) {
    auto first = EventJournal::Create(root);
    auto second = EventJournal::Create(root);
    std::vector<std::thread> writers;
    for (const auto& journal : {first, second}) {
        writers.emplace_back([journal] {
            OperationBinding binding(journal->Context());
            for (int index = 0; index < 50; ++index) CurrentOperationContext()->Emit("test.isolation");
        });
    }
    for (auto& writer : writers) writer.join();
    for (const auto& journal : {first, second}) {
        journal->Flush();
        const auto events = ReadEvents(journal->Directory());
        Require(events.size() == 50, "Independent build lost events");
        for (const auto& event : events) Require(event.GetString("build_id") == journal->Context()->build_id, "Concurrent build contexts leaked");
    }
    auto data = JsonValue::ObjectValue();
    data.Set("oversized", JsonValue::String(std::string(2 * 1024 * 1024, 'x')));
    first->Context()->Emit("test.oversized", std::move(data));
    first->Flush();
    Require(first->HasErrors(), "Oversized record loss was hidden");
    const auto events = ReadEvents(first->Directory());
    Require(events.back().GetString("kind") == "observability.gap", "Dropped final event was not reported durably");
}

void TestCommonTransport(const fs::path& root) {
    auto journal = EventJournal::Create(root);
    std::ostringstream live;
    auto stream = std::make_shared<JsonStreamSink>(live);
    CompositeEventSink transports({stream, journal->Context()->sink});
    std::vector<std::thread> workers;
    for (int worker = 0; worker < 4; ++worker) workers.emplace_back([&, worker] {
        for (int index = 0; index < 25; ++index) {
            auto data = JsonValue::ObjectValue();
            data.Set("index", JsonValue::Number(std::to_string(worker * 25 + index)));
            data.Set("url", JsonValue::String("https://owned-user:owned-secret@example.org/?token=owned-token"));
            transports.Emit({"test.transport", "info", journal->Context()->build_id, "owned-span", "owned-parent", std::move(data)});
        }
    });
    for (auto& worker : workers) worker.join();
    journal->Flush(); Require(!journal->HasErrors(), "Shared transport caused journal errors");
    std::vector<JsonValue> streamed;
    std::istringstream lines(live.str()); std::string line;
    while (std::getline(lines, line)) {
        auto event = JsonValue::Parse(line); Require(event.has_value(), "Concurrent live records interleaved or invalid JSON");
        streamed.push_back(std::move(*event));
    }
    const auto persisted = ReadEvents(journal->Directory());
    Require(streamed.size() == 100 && persisted.size() == 100, "Transport lost concurrent events");
    const std::vector<JsonValue>* transports_records[] = {&streamed, &persisted};
    for (const auto* records : transports_records) {
        const auto producer = records->front().GetString("producer_id");
        Require(std::regex_match(producer, std::regex("[0-9a-f]{32}")), "Missing native producer identity");
        std::set<int> indices; int sequence = 0;
        for (const auto& event : *records) {
            for (const auto* key : {"schema_version", "timestamp", "producer_id", "producer_sequence", "process_id", "thread_id",
                "kind", "severity", "build_id", "span_id", "parent_span_id", "data"})
                Require(event.Get(key), "Live/journal transport schema differs");
            Require(event.Get("schema_version")->Int() == 1 && event.GetString("producer_id") == producer &&
                event.Get("producer_sequence")->Int() == ++sequence, "Producer sequence missing, duplicated or reordered");
            Require(event.Get("process_id")->Int() == GetCurrentProcessId() && event.Get("thread_id")->Int() > 0 &&
                std::regex_match(event.GetString("timestamp"), std::regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z")),
                "Transport discarded actual process/thread/time metadata");
            Require(event.GetString("build_id") == journal->Context()->build_id && event.GetString("span_id") == "owned-span" &&
                event.GetString("parent_span_id") == "owned-parent", "Transport lost operation/span correlation");
            indices.insert(static_cast<int>(event.Get("data")->Get("index")->Int()));
            Require(event.Serialize().find("owned-secret") == std::string::npos && event.Serialize().find("owned-token") == std::string::npos,
                "Common transport exposed secret data");
        }
        Require(indices.size() == 100, "Transport duplicated concurrent payloads");
    }
    Require(streamed.front().GetString("producer_id") != persisted.front().GetString("producer_id"), "Independent transports shared producer identity");
    std::ostringstream replay;
    std::string replay_error;
    Require(EventJournal::Replay(journal->Directory(), 0, 1000, replay, replay_error), "Shared envelopes broke replay");
    std::istringstream replay_lines(replay.str()); std::size_t index = 0;
    while (std::getline(replay_lines, line)) {
        const auto event = JsonValue::Parse(line);
        Require(event && index < persisted.size() && event->Serialize() == persisted[index++].Serialize(), "Replay changed source envelope");
    }
    Require(index == persisted.size(), "Replay lost shared envelopes");
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--child") return Child(argv[2]);
        if (argc == 3 && std::string(argv[1]) == "--parse-tool-log") {
            auto sink = std::make_shared<Collector>();
            auto context = std::make_shared<OperationContext>(OperationContext{sink, NewOperationId(), NewOperationId(), {}});
            ProcessDiagnostics parser(context, L"");
            std::ifstream input(fs::path(argv[2]), std::ios::binary);
            Require(static_cast<bool>(input), "Cannot read preserved tool log");
            char bytes[4096];
            while (input.read(bytes, sizeof(bytes)) || input.gcount()) parser.Feed(std::string(bytes, input.gcount()));
            parser.Finish();
            std::cout << "Observed stack frames: " << parser.StackFrameCount() << '\n';
            return parser.StackFrameCount() ? 0 : 1;
        }
        const fs::path root = fs::temp_directory_path() / ("OPENFRUIT-events-tests-" + NewOperationId());
        TestDiagnosticsAndProgress();
        TestToolStackDiagnostics();
        TestProductionProcessPath(fs::absolute(argv[0]), root);
        TestJournalLossAndIsolation(root);
        TestCommonTransport(root);
        std::cout << "Structured event contracts and production process path: PASS\n";
        std::cout << "Preserved test journals: " << root.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
