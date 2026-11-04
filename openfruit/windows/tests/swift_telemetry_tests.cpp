#include "swift_telemetry.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace OpenFruit;
namespace fs = std::filesystem;

namespace {
void Require(bool value, const char* error) { if (!value) throw std::runtime_error(error); }
std::string Frame(const std::string& json) { return std::to_string(json.size()) + "\n" + json + "\n"; }
class Collector : public EventSink {
public:
    std::vector<OperationEvent> events;
    void Emit(OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
void TestFrames() {
    const std::string began = R"({"kind":"began","name":"compile","pid":1,"inputs":["one.swift","two.swift"]})";
    const std::string finished = R"({"kind":"finished","name":"compile","pid":1,"exit-status":1,"output":"one.swift:3:2: error: expected expression\n"})";
    for (const std::size_t chunk : {1, 3, 17, 4096}) {
        std::vector<JsonValue> records;
        std::string plain;
        SwiftTelemetryParser parser([&](const JsonValue& value) { records.push_back(value); },
            [&](const std::string& text) { plain += text; });
        const std::string text = "warning: literal {braces}\n{\"kind\":\"began\"}\n99999999999999999999999\n";
        const auto stream = text + Frame(began) + "5\nxxxxx\n" + Frame(finished) + "20\ntruncated";
        for (std::size_t offset = 0; offset < stream.size(); offset += chunk)
            parser.Consume(stream.substr(offset, chunk));
        parser.Finish();
        Require(records.size() == 2, "Chunked records lost or arbitrary JSON accepted");
        Require(plain.find(text) == 0 && plain.find("5\nxxxxx") != std::string::npos &&
                plain.find("20\ntruncated") != std::string::npos, "Malformed or truncated text lost");
        std::string windows;
        for (const char byte : Frame(began) + Frame(finished)) {
            if (byte == '\n') windows.push_back('\r');
            windows.push_back(byte);
        }
        records.clear();
        for (std::size_t offset = 0; offset < windows.size(); offset += chunk)
            parser.Consume(windows.substr(offset, chunk));
        parser.Finish();
        Require(records.size() == 2, "Windows transport CRLF broke announced frame sizes");
    }
    std::size_t retained = 0;
    SwiftTelemetryParser parser([](const JsonValue&) {}, [&](const std::string& text) { retained += text.size(); });
    const std::string oversized(200000, 'x');
    parser.Consume(oversized); parser.Finish();
    Require(retained == oversized.size(), "Long nonframed text stopped draining");

    auto sink = std::make_shared<Collector>();
    auto context = std::make_shared<OperationContext>(OperationContext{sink, NewOperationId(), NewOperationId(), {}});
    std::string progress;
    SwiftCompilerTelemetry telemetry(context, [&](const std::string& text) { progress += text; });
    telemetry.Consume(Frame(began) + Frame(finished)); telemetry.Finish();
    Require(progress.find("OPENFRUIT Swift job: started") != std::string::npos &&
            progress.find("OPENFRUIT Swift job: FAILED compile") != std::string::npos &&
            progress.find("[done 0, failed 1, running 0]") != std::string::npos, "compiler job progress not reported");
    bool diagnostic = false;
    bool completion = false;
    for (const auto& event : sink->events) {
        diagnostic |= event.kind == "diagnostic";
        if (event.kind == "compiler.finished") {
            completion = true;
            Require(event.data.Get("inputs") && event.data.Get("inputs")->ArrayItems().size() == 2,
                "Terminal job lost inputs from began record");
            Require(!event.data.Get("completed_sources") && !event.data.Get("percent"),
                "Failed WMO job fabricated source completion");
            Require(event.data.Get("exit_code")->Int() == 1, "Failed job status lost");
        }
    }
    Require(diagnostic && completion, "Embedded compiler diagnostic or job outcome lost");
}
void TestRealCompiler() {
    const auto swift = ToolPaths::SwiftBin({}) / "swiftc.exe";
    if (!fs::is_regular_file(swift)) { std::cout << "Real Swift unavailable; protocol contracts passed\n"; return; }
    const auto scratch = fs::temp_directory_path() / ("OPENFRUIT-swift-events-" + NewOperationId());
    fs::create_directories(scratch);
    std::ofstream(scratch / "Probe.swift") << "let value = 1\n";
    auto sink = std::make_shared<Collector>();
    auto context = std::make_shared<OperationContext>(OperationContext{sink, NewOperationId(), NewOperationId(), {}});
    SwiftCompilerTelemetry telemetry(context, [](const std::string&) {});
    // Channel/adapter contract, not a claim that a host SDK or the iOS app builds.
    const auto result = Win32Process::Run(swift.wstring(),
        {swift.wstring(), L"-parseable-output", L"-c", (scratch / "Probe.swift").wstring(), L"-o", (scratch / "Probe.obj").wstring()},
        L"", {}, nullptr, [&](const std::string& text) { telemetry.Consume(text); });
    telemetry.Finish();
    bool began = false, terminal = false;
    for (const auto& event : sink->events) {
        began |= event.kind == "compiler.began";
        terminal |= event.kind == "compiler.finished" || event.kind == "compiler.signalled";
    }
    std::error_code ec; fs::remove_all(scratch, ec);
    if (!result.launched || !began || !terminal) {
        std::cerr << "Swift=" << swift.string() << " exit=" << result.exit_code << " events=" << sink->events.size()
                  << "\nstderr=" << result.std_err << '\n';
        throw std::runtime_error("Actual Swift stderr did not reach production telemetry adapter");
    }
}
}
int main() {
    try { TestFrames(); TestRealCompiler(); std::cout << "Swift stderr framing and observed jobs: PASS\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
