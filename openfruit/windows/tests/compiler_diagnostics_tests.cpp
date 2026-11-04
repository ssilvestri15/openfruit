#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "json_value.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sstream>

namespace fs = std::filesystem;
using namespace OpenFruit;

// Exercise the production compiler-proxy interface, not a second compiler
// adapter. The compiler path is discovered exactly as in the native pipeline.
int main(int argc, char* argv[]) {
    fs::path scratch;
    try {
        if (argc != 2) throw std::runtime_error("Expected native CLI path");
        const auto clang = ToolPaths::SwiftBin({}) / "clang.exe";
        if (!fs::is_regular_file(clang)) {
            std::cout << "SKIP: managed Swift Clang is unavailable\n";
            return 77;
        }
        scratch = fs::temp_directory_path() /
            ("openfruit-compiler-diagnostics-" + std::to_string(GetCurrentProcessId()));
        fs::create_directories(scratch);
        const auto source = scratch / "probe.c";
        const auto cli = fs::absolute(argv[1]).wstring();
        const auto verify_stream = [&](const ProcessResult& result, bool expect_diagnostic) {
            std::istringstream lines(result.std_out);
            std::string line;
            fs::path journal;
            std::size_t records = 0;
            bool diagnostic = false;
            bool terminal = false;
            std::string producer;
            while (std::getline(lines, line)) {
                const auto event = JsonValue::Parse(line);
                if (!event) throw std::runtime_error("CLI stdout contains non-JSON output: " + line);
                ++records;
                for (const auto* key : {"schema_version", "timestamp", "producer_id", "producer_sequence", "process_id", "thread_id", "parent_span_id"})
                    if (!event->Get(key)) throw std::runtime_error("CLI stream lacks common event envelope metadata");
                if (producer.empty()) producer = event->GetString("producer_id");
                if (producer.size() != 32 || event->GetString("producer_id") != producer ||
                    event->Get("producer_sequence")->Int() != records || event->GetString("timestamp").size() != 24 ||
                    event->Get("process_id")->Int() <= 0 || event->Get("thread_id")->Int() <= 0)
                    throw std::runtime_error("CLI common event identity/sequence/time metadata is invalid");
                const auto data = event->Get("data");
                if (!data) throw std::runtime_error("Missing event data");
                if (event->GetString("kind") == "task.started" && data->GetString("name") == "cli.command") {
                    journal = data->GetString("journal_directory");
                }
                diagnostic |= event->GetString("kind") == "diagnostic";
                terminal |= event->GetString("kind") == "task.completed" && data->GetString("name") == "cli.command";
            }
            if (!records || !terminal || (expect_diagnostic && !diagnostic))
                throw std::runtime_error("Missing command outcome or compiler diagnostic in JSON stream: " + result.std_out);
            if (journal.empty() || !fs::is_regular_file(journal / "events.jsonl"))
                throw std::runtime_error("JSON command did not preserve its journal");
            std::ifstream persisted(journal / "events.jsonl");
            std::size_t journal_records = 0;
            while (std::getline(persisted, line)) {
                if (!JsonValue::Parse(line)) throw std::runtime_error("Invalid persisted journal record");
                ++journal_records;
            }
            if (journal_records != records) throw std::runtime_error("Stream and journal lost different events");
        };
        for (bool valid : {true, false}) {
            std::ofstream(source) << (valid ? "int value = 1;\n" : "int value = ;\n");
            int normal_exit = -1;
            for (bool json : {false, true}) {
                const auto result = Win32Process::Run(cli,
                    {cli, L"-x", L"c", L"-fsyntax-only", source.wstring()}, L"",
                    {{L"OPENFRUIT_COMPILER_PROXY_REAL", clang.wstring()},
                     {L"OPENFRUIT_JSON_DIAGNOSTICS", json ? L"1" : L"0"},
                     {L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L""},
                     {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", L""}});
                if (!result.launched || (result.exit_code == 0) != valid)
                    throw std::runtime_error("Diagnostics changed compiler success/failure: " + result.std_err);
                if (!json) normal_exit = result.exit_code;
                else if (normal_exit != result.exit_code)
                    throw std::runtime_error("Normal and JSON modes have different exit codes");
                if (!valid && (result.std_err.find("probe.c:1:") == std::string::npos ||
                               result.std_err.find("error:") == std::string::npos))
                    throw std::runtime_error("Compiler source diagnostic was lost");
                if (result.std_err.find("invalid value 'json'") != std::string::npos)
                    throw std::runtime_error("Unsupported diagnostic format reached Clang");
            }
            const auto streamed = Win32Process::Run(cli,
                {cli, L"-x", L"c", L"-fsyntax-only", source.wstring(), L"--diagnostics=json"}, L"",
                {{L"OPENFRUIT_COMPILER_PROXY_REAL", clang.wstring()},
                 {L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L""},
                 {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", L""},
                 {L"OPENFRUIT_USER_STATE", scratch.wstring()}});
            if ((streamed.exit_code == 0) != valid) throw std::runtime_error("JSON CLI changed compiler outcome");
            verify_stream(streamed, !valid);
        }
        for (const auto command : {L"version", L"unknown-diagnostics-test-command"}) {
            const auto normal = Win32Process::Run(cli, {cli, command});
            const auto streamed = Win32Process::Run(cli, {cli, command, L"--diagnostics=json"}, L"",
                {{L"OPENFRUIT_USER_STATE", scratch.wstring()}});
            if (normal.exit_code != streamed.exit_code) throw std::runtime_error("JSON CLI changed command outcome");
            verify_stream(streamed, false);
        }
        fs::remove_all(scratch);
        std::cout << "PASS: production proxy preserves compiler semantics in both modes\n";
        return 0;
    } catch (const std::exception& error) {
        if (!scratch.empty()) { std::error_code ec; fs::remove_all(scratch, ec); }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
