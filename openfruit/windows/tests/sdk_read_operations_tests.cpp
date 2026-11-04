#include "sdk_read_operations.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void Write(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary); output << bytes;
    Require(output.good(), "Owned fixture write failed");
}
void Layout(const fs::path& sdk) {
    fs::create_directories(sdk / "usr" / "lib");
    fs::create_directories(sdk / "System" / "Library" / "Frameworks");
    Write(sdk / "SDKSettings.json", "{\"owned_layout_fixture\":true}\n");
}
struct Stamp {
    fs::path path;
    std::string bytes;
    fs::file_time_type modified;
    explicit Stamp(const fs::path& value) : path(value), bytes(Read(value)), modified(fs::last_write_time(value)) {}
    bool Unchanged() const { return Read(path) == bytes && fs::last_write_time(path) == modified; }
};
struct Sink : EventSink {
    std::vector<OperationEvent> events;
    void Emit(OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
using Environment = std::vector<std::pair<std::wstring, std::wstring>>;
Environment ChildEnvironment(const fs::path& state, const fs::path& home, const fs::path& profile,
                             const fs::path& override_sdk = {}) {
    return {{L"OPENFRUIT_USER_STATE", state.wstring()}, {L"OPENFRUIT_HOME", home.wstring()},
        {L"USERPROFILE", profile.wstring()}, {L"OPENFRUIT_IOS_SDK", override_sdk.wstring()},
        {L"OPENFRUIT_CACHE_ROOT", (home / "cache").wstring()}, {L"OPENFRUIT_EVENT_DIRECTORY", L""},
        {L"OPENFRUIT_COMPILER_PROXY_REAL", L""}, {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", L""},
        {L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L""}};
}
JsonValue Snapshot(const ProcessResult& result, const char* kind, int expected_exit) {
    Require(result.launched && result.exit_code == expected_exit && !result.output_truncated,
        "Native SDK query failed or reported a different status");
    std::istringstream records(result.std_out);
    std::string line;
    std::optional<JsonValue> snapshot;
    while (std::getline(records, line)) {
        const auto event = JsonValue::Parse(line);
        Require(event.has_value(), "SDK machine stream contains non-JSON output");
        const auto* data = event->Get("data");
        Require(event->GetString("kind") != "process.started" &&
            !(event->GetString("kind") == "task.started" && data && data->GetString("name") == "process"),
            "Read-only SDK query attempted to launch a child tool");
        if (event->GetString("kind") == kind) {
            Require(!snapshot.has_value() && event->Get("data"), "SDK snapshot missing data or duplicated");
            snapshot = *event->Get("data");
        }
    }
    Require(snapshot.has_value(), "SDK query did not emit its typed result");
    if (snapshot->GetString("status") == "available")
        Require(snapshot->Get("layout") && snapshot->Get("layout")->Get("usable") &&
            snapshot->Get("layout")->Get("usable")->Bool(), "Available query result has an incomplete observed layout");
    return *snapshot;
}
std::wstring EnvironmentValue(const wchar_t* name) {
    const auto size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    value.resize(GetEnvironmentVariableW(name, value.data(), size)); return value;
}
}
int main(int argc, char** argv) {
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-read-" + NewOperationId());
    try {
        Require(argc == 2, "Pass the actual native CLI candidate path");
        const auto cli = fs::absolute(fs::path(argv[1])).wstring();
        const auto home_a = root / "a" / "managed";
        const auto home_b = root / "b" / "managed";
        const auto sdk_a = root / "a" / "registered.sdk";
        const auto sdk_b = root / "b" / "registered.sdk";
        Layout(sdk_a); Layout(sdk_b);
        const auto managed_a = home_a / "sdk" / "ios" / "26" / "iPhoneOS.sdk";
        const auto latest_a = home_a / "sdk" / "ios" / "27" / "iPhoneOS.sdk";
        const auto latest_b = home_b / "sdk" / "ios" / "28" / "iPhoneOS.sdk";
        Layout(managed_a); Layout(latest_a); Layout(latest_b);
        fs::create_directories(home_a / "sdk" / "ios" / "29" / "iPhoneOS.sdk"); // incomplete: not a winner
        SDKReadRequest a, b;
        a.managed_home = home_a; b.managed_home = home_b;
        a.configuration.ios_sdk_version = L"26";
        a.configuration.ios_sdk_paths[L"26"] = sdk_a.wstring();
        a.configuration.ios_sdk_paths[L"27"] = (root / "missing-registration").wstring();
        a.configuration.sdk_path = (root / "stale-selected-path").wstring();
        b.configuration.sdk_path = sdk_b.wstring();
        const auto sink = std::make_shared<Sink>();
        const auto context = std::make_shared<OperationContext>(); context->sink = sink;
        const auto before_home = EnvironmentValue(L"OPENFRUIT_HOME");
        const auto before_sdk = EnvironmentValue(L"OPENFRUIT_IOS_SDK");
        {
            OperationBinding binding(context);
            const auto entries = SDKReadOperations::List(a);
            Require(entries.entries.size() == 2 && entries.entries[0].catalog.selected &&
                entries.entries[0].catalog.layout.Usable() && !entries.entries[1].catalog.layout.Usable(),
                "Catalog rows lost registration/selection/layout semantics");
            Require(entries.entries[0].provenance == SDKReadProvenance::ConfiguredRegistration,
                "Registered catalog row has wrong provenance");
            Require(SDKReadOperations::List({}).entries.empty(), "Empty catalog fabricated an SDK");
            SDKReadRequest relative_catalog;
            relative_catalog.configuration.ios_sdk_version = L"relative";
            relative_catalog.configuration.ios_sdk_paths[L"relative"] = fs::path(".").wstring();
            const auto relative_registration = SDKReadOperations::List(relative_catalog);
            Require(relative_registration.entries.size() == 1 && relative_registration.entries[0].catalog.selected &&
                !relative_registration.entries[0].catalog.layout.directory &&
                !relative_registration.entries[0].catalog.layout.Usable(), "Relative registration observed ambient CWD");
            relative_catalog.configuration.ios_sdk_paths.clear();
            relative_catalog.configuration.sdk_path = fs::path(".").wstring();
            const auto relative_path_only = SDKReadOperations::List(relative_catalog);
            Require(relative_path_only.entries.size() == 1 &&
                relative_path_only.entries[0].provenance == SDKReadProvenance::SelectedPathOnly &&
                !relative_path_only.entries[0].catalog.layout.directory &&
                !relative_path_only.entries[0].catalog.layout.Usable(), "Relative selected path observed ambient CWD");
            const auto path_a = SDKReadOperations::Path(a);
            Require(path_a.status == SDKReadStatus::Available && path_a.path == sdk_a &&
                path_a.provenance == SDKReadProvenance::ConfiguredRegistration,
                "Selected version did not resolve from the authoritative registration");
            const auto path_b = SDKReadOperations::Path(b);
            Require(path_b.path == sdk_b && path_b.provenance == SDKReadProvenance::SelectedPathOnly &&
                SDKReadOperations::List(b).entries[0].provenance == SDKReadProvenance::SelectedPathOnly,
                "Path-only legacy configuration lost provenance");
            auto overridden = a; overridden.sdk_override = sdk_b;
            Require(SDKReadOperations::Path(overridden).path == sdk_b &&
                SDKReadOperations::Path(overridden).provenance == SDKReadProvenance::ExplicitOverride,
                "Explicit SDK override did not remain authoritative");
            overridden.sdk_override = root / "missing-override";
            const auto unavailable = SDKReadOperations::Path(overridden);
            Require(unavailable.status == SDKReadStatus::Unavailable && unavailable.path.empty() &&
                unavailable.provenance == SDKReadProvenance::ExplicitOverride,
                "Missing explicit override silently selected a managed SDK");
            overridden.sdk_override = "relative-sdk";
            Require(SDKReadOperations::Path(overridden).status == SDKReadStatus::InvalidRequest,
                "Relative request used process working-directory state");
            auto stale = a; stale.configuration.ios_sdk_version = L"27";
            const auto fallback = SDKReadOperations::Path(stale);
            Require(fallback.path == latest_a && fallback.provenance == SDKReadProvenance::ManagedDiscovery &&
                stale.configuration.ios_sdk_version == L"27" && stale.configuration.sdk_path == a.configuration.sdk_path,
                "Persisted stale path fallback mutated selection or chose a partial SDK");
            auto relative_persisted = a;
            relative_persisted.configuration.ios_sdk_version.clear();
            relative_persisted.configuration.ios_sdk_paths.clear();
            relative_persisted.configuration.sdk_path = L"relative-stale-sdk";
            const auto relative_fallback = SDKReadOperations::Path(relative_persisted);
            Require(relative_fallback.path == latest_a && relative_fallback.provenance == SDKReadProvenance::ManagedDiscovery,
                "Stale relative persisted path bound lookup to ambient CWD");
            SDKReadRequest empty; empty.managed_home = root / "absent-managed-home";
            Require(SDKReadOperations::Path(empty).status == SDKReadStatus::Unavailable &&
                !fs::exists(empty.managed_home), "Read-only empty lookup acquired or created an SDK");
            auto inspect_a = std::async(std::launch::async, [&]() {
                for (int i = 0; i < 100; ++i) {
                    const auto value = SDKReadOperations::Path({{}, home_a, {}});
                    Require(value.path == latest_a, "Concurrent root A leaked another request");
                }
            });
            auto inspect_b = std::async(std::launch::async, [&]() {
                for (int i = 0; i < 100; ++i) {
                    const auto value = SDKReadOperations::Path({{}, home_b, {}});
                    Require(value.path == latest_b, "Concurrent root B leaked another request");
                }
            });
            inspect_a.get(); inspect_b.get();
            Require(sink->events.empty(), "Read-only API emitted an acquisition/process operation");
        }
        Require(EnvironmentValue(L"OPENFRUIT_HOME") == before_home && EnvironmentValue(L"OPENFRUIT_IOS_SDK") == before_sdk,
            "Read-only API modified process environment");
        const auto state = root / "a" / "state";
        const auto profile = root / "a" / "profile";
        const auto config_path = state / "config.toml";
        a.configuration.OPENFRUIT_home = home_a.wstring();
        a.configuration.user_state_root = state.wstring();
        a.configuration.secrets_path = (root / "a" / "legacy-secrets.json").wstring();
        Write(a.configuration.secrets_path, "{\"signing_password\":\"owned-plaintext-must-never-be-loaded\"}\n");
        Write(profile / ".OPENFRUIT" / "secrets.json", "{\"signing_password\":\"owned-legacy-secret\"}\n");
        Require(a.configuration.Save(config_path.wstring()), "Could not publish owned query configuration");
        const Stamp configuration(config_path), secret(a.configuration.secrets_path), legacy_secret(profile / ".OPENFRUIT" / "secrets.json");
        const Stamp sdk_settings(sdk_a / "SDKSettings.json");
        const auto env = ChildEnvironment(state, home_a, profile);
        const auto invoke = [&](const std::vector<std::wstring>& arguments, const Environment& environment) {
            auto args = arguments; args.insert(args.begin(), cli);
            return Win32Process::Run(cli, args, L"", environment);
        };
        const auto list_api = SDKReadOperations::List(a).ToJson().Serialize();
        const auto path_api = SDKReadOperations::Path(a).ToJson().Serialize();
        Require(Snapshot(invoke({L"sdk", L"list", L"--diagnostics=json"}, env), "sdk.list.snapshot", 0).Serialize() == list_api,
            "Native list CLI and typed API differ");
        Require(Snapshot(invoke({L"sdk", L"path", L"--diagnostics=json"}, env), "sdk.path.snapshot", 0).Serialize() == path_api,
            "Native path CLI and typed API differ");
        Require(Snapshot(invoke({L"sdk", L"--diagnostics=json"}, env), "sdk.path.snapshot", 0).Serialize() == path_api,
            "Default SDK command did not use the read-only path operation");
        const auto plain_path = invoke({L"sdk", L"path"}, env);
        auto plain_path_text = plain_path.std_out;
        while (!plain_path_text.empty() && (plain_path_text.back() == '\n' || plain_path_text.back() == '\r'))
            plain_path_text.pop_back();
        Require(plain_path.success && plain_path_text == Win32Process::ToNarrow(sdk_a.wstring()),
            "Plain path renderer changed compatibility output");
        const auto plain_list = invoke({L"sdk", L"list"}, env);
        Require(plain_list.success && plain_list.std_out.find("Configured iOS SDKs:") != std::string::npos &&
            plain_list.std_out.find("26 * ") != std::string::npos && plain_list.std_out.find("[layout incomplete]") != std::string::npos,
            "Plain list renderer lost selection or incomplete-layout state");
        const auto failed_override_env = ChildEnvironment(state, home_a, profile, root / "missing-override");
        auto failed_override = a; failed_override.sdk_override = root / "missing-override";
        Require(Snapshot(invoke({L"sdk", L"path", L"--diagnostics=json"}, failed_override_env), "sdk.path.snapshot", 1).Serialize() ==
            SDKReadOperations::Path(failed_override).ToJson().Serialize(), "CLI silently replaced an invalid explicit override");
        Require(invoke({L"sdk", L"list", L"unexpected"}, env).exit_code == 2 &&
            invoke({L"sdk", L"path", L"unexpected"}, env).exit_code == 2, "SDK query accepted unknown extra arguments");
        Require(configuration.Unchanged() && secret.Unchanged() && legacy_secret.Unchanged() && sdk_settings.Unchanged() &&
            !fs::exists(state / "credentials") && !fs::exists(home_a / "cache") && !fs::exists(home_a / "toolchains"),
            "SDK reads initialized credentials, toolchains, caches or rewrote observed files");
        // Missing TOML/installation and a legacy config are separate cases.
        // The latter remains readable without migrating it to config.toml.
        const auto missing_state = root / "missing" / "state";
        const auto missing_home = root / "missing" / "home";
        const auto missing_profile = root / "missing" / "profile";
        const auto missing_env = ChildEnvironment(missing_state, missing_home, missing_profile);
        SDKReadRequest missing_request; missing_request.managed_home = missing_home;
        Require(Snapshot(invoke({L"sdk", L"list", L"--diagnostics=json"}, missing_env), "sdk.list.snapshot", 0).Serialize() ==
            SDKReadOperations::List(missing_request).ToJson().Serialize(), "Missing config fabricated catalog entries");
        Require(Snapshot(invoke({L"sdk", L"path", L"--diagnostics=json"}, missing_env), "sdk.path.snapshot", 1).Serialize() ==
            SDKReadOperations::Path(missing_request).ToJson().Serialize(), "Missing SDK reported an available path");
        Require(!fs::exists(missing_state / "config.toml") && !fs::exists(missing_state / "credentials") &&
            !fs::exists(missing_home), "Missing configuration lookup initialized managed state");
        const auto legacy_config = missing_profile / ".OPENFRUIT" / "config.json";
        Write(legacy_config, "{\"sdk_path\":\"" + sdk_b.generic_string() + "\"}\n");
        const Stamp legacy_configuration(legacy_config);
        // The legacy reader preserves its supplied spelling. The JSON fixture
        // uses forward slashes, so expected API input must use those same bytes.
        missing_request.configuration.sdk_path = sdk_b.generic_wstring();
        Require(Snapshot(invoke({L"sdk", L"path", L"--diagnostics=json"}, missing_env), "sdk.path.snapshot", 0).Serialize() ==
            SDKReadOperations::Path(missing_request).ToJson().Serialize(), "Read-only legacy configuration was not preserved");
        Require(legacy_configuration.Unchanged() && !fs::exists(missing_state / "config.toml") && !fs::exists(missing_home),
            "Legacy configuration was migrated by a read-only query");
        std::cout << "Read-only SDK catalog/path, concurrency and native CLI parity: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; owned fixture retained: " << root << '\n'; return 1;
    }
}
