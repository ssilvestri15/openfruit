#include "interface_builder_compiler.hpp"
#include "event_journal.hpp"
#include "content_hash.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void CheckFailure(const fs::path& root, const char* name, const char* extension,
                  const char* xml, const char* reason, bool expect_original_warning) {
    const auto bundle = root / name;
    fs::create_directories(bundle);
    const auto source = bundle / (std::string("Invalid") + extension);
    {
        std::ofstream stream(source, std::ios::binary);
        stream << xml;
        Require(static_cast<bool>(stream), "Cannot create owned invalid resource");
    }
    const auto original_hash = Sha256File(source);
    Require(original_hash.has_value(), "Cannot hash owned input");
    auto journal = EventJournal::Create(root / "journals");
    std::string error;
    {
        OperationBinding binding(journal->Context());
        Require(!InterfaceBuilderCompiler::CompileUncompiledInBundle(bundle, error),
                "Invalid original resource unexpectedly compiled");
    }
    journal->Flush();
    Require(!journal->HasErrors(), "Resource failure journal unavailable");
    Require(!error.empty(), "Resource failure lacks caller error");
    Require(Sha256File(source) == original_hash, "Failed source content changed");
    std::ifstream stream(journal->Directory() / "events.jsonl", std::ios::binary);
    Require(static_cast<bool>(stream), "Resource journal missing");
    std::string text, resource_span;
    bool saw_exception = false, saw_original_warning = false, completed = false;
    while (std::getline(stream, text)) {
        auto record = JsonValue::Parse(text);
        Require(record.has_value(), "Invalid event JSON");
        const auto* data = record->Get("data");
        Require(data != nullptr, "Event data absent");
        const auto kind = record->GetString("kind");
        if (kind == "task.started" && data->GetString("name") == "resource.interface_builder.file")
            resource_span = record->GetString("span_id");
        if (kind == "diagnostic" && data->GetString("code") == "OPENIB-W0001") {
            Require(!saw_exception, "Original warning reordered after exception");
            Require(data->GetString("severity") == "warning", "Original warning severity lost");
            Require(data->GetString("origin") != "openfruit.adapter", "Original warning relabelled as adapter error");
            saw_original_warning = true;
        }
        if (kind == "diagnostic" && data->GetString("origin") == "openfruit.adapter") {
            Require(!saw_exception && !completed, "Exception duplicated or emitted after completion");
            Require(data->GetString("code") == "OPENFRUIT-IB-EXCEPTION", "Adapter exception classification missing");
            Require(record->GetString("severity") == "error" && data->GetString("severity") == "error",
                    "Exception error severity lost");
            Require(data->GetString("tool") == "openib" && !data->GetString("diagnostic_id").empty(),
                    "Exception diagnostic identity missing");
            Require(data->GetString("message").find(reason) != std::string::npos,
                    "Original exception reason lost");
            Require(data->GetString("file") == source.string(), "Exception source ownership lost");
            Require(!resource_span.empty() && record->GetString("span_id") == resource_span,
                    "Exception resource span lost");
            Require(!data->Get("line") && !data->Get("column") && !data->Get("node"),
                    "Exception acquired invented structured coordinates");
            saw_exception = true;
        }
        if (kind == "task.completed" && data->GetString("name") == "resource.interface_builder.file") {
            Require(saw_exception, "Resource completed before exception diagnostic");
            Require(data->GetString("state") == "failed", "Invalid resource completion reported success");
            completed = true;
        }
    }
    Require(saw_exception && completed, "Real OpenIB exception was not journalled");
    Require(saw_original_warning == expect_original_warning, "Original warning preservation differs");
}
}

int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-ib-failure-" + NewOperationId());
    try {
        // Exercise the real compiler's parser/model throws through the public
        // resource adapter. No exception/diagnostic/compiler output is injected.
        CheckFailure(root, "root", ".xib", "<?xml version=\"1.0\"?><wrongRoot/>",
                     "document root must be <document>", false);
        CheckFailure(root, "scenes", ".storyboard",
                     "<?xml version=\"1.0\"?><document type=\"com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB\" targetRuntime=\"owned-invalid-runtime\"/>",
                     "Storyboard has no <scenes> element", true);
        CheckFailure(root, "malformed", ".xib", "<?xml version=\"1.0\"?><document><objects></document>",
                     "Mismatched closing tag", false);
        std::error_code ec;
        fs::remove_all(root, ec);
        std::cout << "Interface Builder failure diagnostics tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << "\nFixture retained: " << root << '\n';
        return 1;
    }
}
