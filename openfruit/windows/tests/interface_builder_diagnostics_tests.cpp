#include "interface_builder_compiler.hpp"
#include "event_journal.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<JsonValue> ReadEvents(const fs::path& directory) {
    std::ifstream input(directory / "events.jsonl", std::ios::binary);
    Require(static_cast<bool>(input), "Interface Builder journal missing");
    std::vector<JsonValue> records;
    std::string line;
    while (std::getline(input, line)) {
        auto value = JsonValue::Parse(line);
        Require(value.has_value(), "Interface Builder journal has invalid JSON");
        records.push_back(std::move(*value));
    }
    return records;
}

void CheckDiagnostic(const std::vector<JsonValue>& records, const fs::path& source,
                     const char* code, const char* severity, int line, bool succeeded) {
    std::string resource_span, phase_span;
    std::size_t diagnostic_index = records.size(), completion_index = records.size();
    unsigned matched = 0;
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto& record = records[index];
        const auto* data = record.Get("data");
        Require(data != nullptr, "Event data missing");
        if (record.GetString("kind") == "task.started") {
            if (data->GetString("name") == "resource.interface_builder")
                phase_span = record.GetString("span_id");
            if (data->GetString("name") == "resource.interface_builder.file") {
                resource_span = record.GetString("span_id");
                Require(record.GetString("parent_span_id") == phase_span,
                        "Resource task lost phase parent");
            }
        }
        if (record.GetString("kind") == "diagnostic" && data->GetString("code") == code) {
            ++matched;
            diagnostic_index = index;
            Require(record.GetString("severity") == severity && data->GetString("severity") == severity,
                    "Original OpenIB diagnostic severity lost");
            Require(data->GetString("tool") == "openib" && !data->GetString("diagnostic_id").empty(),
                    "Original OpenIB diagnostic identity lost");
            Require(data->GetString("file") == source.string(), "Diagnostic source path lost");
            Require(data->Get("line") && data->Get("line")->Int() == line, "Diagnostic source line lost");
            Require(data->Get("column") == nullptr, "Invented OpenIB source column");
            Require(!data->GetString("message").empty(), "Diagnostic message lost");
            Require(record.GetString("span_id") == resource_span, "Diagnostic lost resource task ownership");
        }
        if (record.GetString("kind") == "task.completed" &&
            data->GetString("name") == "resource.interface_builder.file") {
            completion_index = index;
            Require(data->GetString("state") == (succeeded ? "succeeded" : "failed"),
                    "Resource task outcome wrong");
        }
    }
    Require(matched == 1, "Original typed diagnostic missing or duplicated");
    Require(diagnostic_index < completion_index, "Diagnostic emitted after resource failure/completion");
}

void CompileCase(const fs::path& root, const char* name, const char* xml,
                 const char* code, const char* severity, int line, bool expected_success) {
    const auto bundle = root / name;
    fs::create_directories(bundle);
    const auto source = bundle / (expected_success ? "Warnings.xib" : "Invalid.storyboard");
    {
        std::ofstream file(source, std::ios::binary);
        file << xml;
        Require(static_cast<bool>(file), "Cannot create owned Interface Builder fixture");
    }
    auto journal = EventJournal::Create(root / "journals");
    std::string error;
    bool result;
    {
        OperationBinding binding(journal->Context());
        result = InterfaceBuilderCompiler::CompileUncompiledInBundle(bundle, error);
    }
    journal->Flush();
    Require(!journal->HasErrors(), "Interface Builder event journal failed");
    Require(result == expected_success, "Actual OpenIB compiler outcome differs from fixture contract");
    Require(expected_success ? error.empty() : !error.empty(), "Interface Builder failure detail missing");
    const auto records = ReadEvents(journal->Directory());
    CheckDiagnostic(records, source, code, severity, line, expected_success);
    if (expected_success) {
        unsigned unlocated_warnings = 0;
        for (const auto& record : records) {
            const auto* data = record.Get("data");
            if (record.GetString("kind") == "diagnostic" &&
                data && data->GetString("code") == "OPENIB-W1000") {
                ++unlocated_warnings;
                Require(record.GetString("severity") == "warning" &&
                        data->GetString("file") == source.string(), "Unlocated warning provenance lost");
                Require(data->Get("line") == nullptr && data->Get("column") == nullptr,
                        "Unlocated OpenIB warning acquired invented coordinates");
            }
        }
        Require(unlocated_warnings == 1, "Success lost the original catalogue warning");
        Require(fs::is_regular_file(bundle / "Warnings.nib"), "Actual OpenIB NIB output missing");
        Require(!fs::exists(source), "Compiled XML resource was not removed");
    } else Require(fs::is_regular_file(source), "Failed input was discarded");
}
}

int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-ib-diagnostics-" + NewOperationId());
    try {
        // Owned source documents invoke the production adapter and real OpenIB;
        // no diagnostic objects or precompiled resources are injected.
        CompileCase(root, "warning",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<document type=\"com.apple.InterfaceBuilder3.CocoaTouch.XIB\" targetRuntime=\"iOS.CocoaTouch\">\n"
            "<objects><view id=\"owned-view\">\n"
            "<ownedUnsupportedChild/>\n"
            "</view></objects></document>\n",
            "OPENIB-W1200", "warning", 4, true);
        CompileCase(root, "error",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<document type=\"com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB\" targetRuntime=\"iOS.CocoaTouch\">\n"
            "<scenes>\n"
            "<scene sceneID=\"owned-invalid\"/>\n"
            "</scenes></document>\n",
            "OPENIB-E0101", "error", 4, false);
        std::error_code ec;
        fs::remove_all(root, ec);
        std::cout << "Interface Builder diagnostics tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\nFixture retained: " << root << '\n';
        return 1;
    }
}
