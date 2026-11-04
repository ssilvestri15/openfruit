#include "event_journal.hpp"
#include "win32_process.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* error) { if (!value) throw std::runtime_error(error); }
std::string Read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream), {});
}
}
int main(int argc, char** argv) {
    try {
        Require(argc == 2, "Expected native CLI path");
        const auto root = fs::temp_directory_path() / ("OPENFRUIT-capabilities-" + NewOperationId());
        fs::create_directories(root);
        const auto configuration = root / "config.toml";
        const auto home = root / "installation";
        const auto cli = fs::absolute(argv[1]).wstring();
        const auto invoke = [&](bool json) {
            std::vector<std::wstring> args{cli, L"capabilities"};
            if (json) args.push_back(L"--diagnostics=json");
            return Win32Process::Run(cli, args, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()},
                {L"OPENFRUIT_HOME", home.wstring()}, {L"OPENFRUIT_EVENT_DIRECTORY", L""},
                {L"OPENFRUIT_COMPILER_PROXY_REAL", L""}, {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", L""},
                {L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L""}});
        };
        const auto pristine = invoke(false);
        Require(pristine.success && JsonValue::Parse(pristine.std_out).has_value(), "Pristine capability CLI failed");
        Require(!fs::exists(configuration) && !fs::exists(root / "credentials") && !fs::exists(home),
            "Read-only discovery initialized persistent state");
        // Authoritative user configuration names missing prerequisite paths;
        // discovery must report their absence, never pretend a tool is ready.
        const auto missing = (root / "missing").generic_string();
        std::ofstream(configuration) << "[toolchains]\nswift = \"" << missing << "\"\nllvm = \"" << missing
            << "\"\n[sdk.ios]\npath = \"" << missing << "\"\n[tools]\nzsign = \"" << missing
            << "\"\npymobiledevice3 = \"" << missing << "\"\n";
        const auto before = Read(configuration);
        const auto written = fs::last_write_time(configuration);
        const auto plain = invoke(false);
        const auto parsed = JsonValue::Parse(plain.std_out);
        Require(plain.success && parsed.has_value(), "Capability snapshot is not JSON");
        const auto operations = parsed->Get("operations");
        const auto tools = parsed->Get("toolchains");
        Require(operations && operations->GetString("build") == "unavailable" &&
            operations->GetString("sdk_auto_selection") == "unavailable" && operations->GetString("sign") == "unavailable",
            "Missing native prerequisites advertised as ready");
        Require(operations->GetString("native_darwin_plugins") == "unavailable" &&
            operations->GetString("zero_wsl_build") == "unsupported" &&
            operations->GetString("ide_operation_adapter") == "unsupported" &&
            operations->GetString("valid_signed_ipa_verification") == "unsupported",
            "Missing prerequisites or unsupported architecture gate advertised as supported");
        const auto* native_detail = parsed->Get("operation_details")->Get("native_darwin_plugins");
        Require(native_detail && native_detail->Get("implementation_present")->Bool() &&
            !native_detail->Get("prerequisites_present")->Bool() &&
            native_detail->GetString("closure_validation") == "not_inspected" &&
            !native_detail->Get("plugin_execution_verified")->Bool() &&
            !parsed->Get("tool_execution_verified")->Bool(), "Native implementation and verification conflated");
        Require(tools && !tools->Get("swift_wmo")->Bool() && !tools->Get("lld_mach_o")->Bool() &&
            !tools->Get("ios_sdk_layout")->Bool() && !tools->Get("wsl2_bridge"), "Capability tool flags misrepresent inventory");
        const auto streamed = invoke(true);
        Require(streamed.success, "JSON capability command failed");
        std::istringstream records(streamed.std_out); std::string line; bool snapshot = false;
        while (std::getline(records, line)) {
            const auto event = JsonValue::Parse(line);
            Require(event.has_value(), "Machine capability stream contains human text");
            Require(event->GetString("kind") != "process.started", "Capability inventory launched a tool");
            if (event->GetString("kind") == "capabilities.snapshot") {
                snapshot = true;
                Require(event->Get("data")->Serialize() == parsed->Serialize(), "Machine capability snapshot differs from CLI");
            }
        }
        Require(snapshot, "Machine stream lost capability result");
        Require(Read(configuration) == before && fs::last_write_time(configuration) == written &&
            !fs::exists(root / "credentials") && !fs::exists(home), "Discovery mutated configuration or credentials");

        // Owned placeholder files test presence only. They are intentionally NOT
        // executable binaries, an admitted provider or a valid Darwin closure.
        const auto sdk = home / "sdk" / "owned.sdk";
        fs::create_directories(sdk / "usr" / "lib");
        fs::create_directories(sdk / "System" / "Library" / "Frameworks");
        fs::create_directories(home / "bin");
        std::ofstream(sdk / "SDKSettings.json") << "{}";
        std::ofstream(home / "bin" / "openfruit-macro-host.exe") << "owned presence-only placeholder";
        std::ofstream(home / "bin" / "unicorn.dll") << "owned presence-only placeholder";
        std::ofstream(configuration) << "[toolchains]\nswift = \"" << missing << "\"\nllvm = \"" << missing
            << "\"\n[sdk.ios]\npath = \"" << sdk.generic_string() << "\"\n[tools]\nzsign = \"" << missing
            << "\"\npymobiledevice3 = \"" << missing << "\"\n";
        const auto metadata_only = [&]() {
            const auto result = invoke(false);
            auto value = JsonValue::Parse(result.std_out);
            Require(result.success && value.has_value(), "Presence-only inventory failed");
            return *value;
        };
        Require(metadata_only().Get("operations")->GetString("native_darwin_plugins") == "unavailable",
            "Missing provider receipt advertised as present");
        fs::create_directories(sdk / "darwin-provider");
        const auto receipt = sdk / "darwin-provider" / "provider.json";
        std::ofstream(receipt) << "owned deliberately invalid provider metadata";
        const auto config_bytes = Read(configuration), receipt_bytes = Read(receipt);
        const auto config_time = fs::last_write_time(configuration), receipt_time = fs::last_write_time(receipt);
        const auto present = metadata_only();
        const auto* present_detail = present.Get("operation_details")->Get("native_darwin_plugins");
        Require(present.Get("operations")->GetString("native_darwin_plugins") == "implemented" &&
            present_detail->Get("prerequisites_present")->Bool() &&
            present_detail->GetString("provider_validation") == "not_inspected" &&
            present_detail->GetString("closure_validation") == "not_inspected" &&
            !present_detail->Get("plugin_execution_verified")->Bool() &&
            !present.Get("tool_execution_verified")->Bool(), "Presence-only snapshot fabricated runtime verification");
        Require(Read(configuration) == config_bytes && Read(receipt) == receipt_bytes &&
            fs::last_write_time(configuration) == config_time && fs::last_write_time(receipt) == receipt_time &&
            !fs::exists(root / "credentials"), "Metadata inventory mutated controlled inputs");
        fs::remove(home / "bin" / "unicorn.dll");
        Require(metadata_only().Get("operations")->GetString("native_darwin_plugins") == "unavailable",
            "Missing Unicorn prerequisite advertised as present");
        std::cout << "Read-only native capability inventory and CLI propagation: PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
