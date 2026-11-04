#include "sdk_selection.hpp"
#include "sdk_usage.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <vector>
namespace fs = std::filesystem;
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
struct Sink : OpenFruit::EventSink {
    std::vector<OpenFruit::OperationEvent> events;
    void Emit(OpenFruit::OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-selection-" + OpenFruit::NewOperationId());
    const auto sdk = root / "sdk";
    const auto config_path = root / "config.toml";
    fs::create_directories(sdk / "usr" / "lib");
    fs::create_directories(sdk / "System" / "Library" / "Frameworks");
    { std::ofstream settings(sdk / "SDKSettings.json"); settings << "{}"; }
    OpenFruit::Config config;
    config.user_state_root = root.wstring();
    config.ios_sdk_version = L"26";
    config.sdk_path = (root / "previous-sdk").wstring();
    config.ios_sdk_paths[L"26"] = config.sdk_path;
    config.ios_sdk_paths[L"27"] = sdk.wstring();
    config.ios_sdk_paths[L"28"] = (root / "missing").wstring();
    config.ios_sdk_paths[L"29"] = L"relative-sdk";
    if (!config.Save(config_path.wstring())) return 3;
    const auto previous = Read(config_path);
    auto sink = std::make_shared<Sink>();
    auto context = std::make_shared<OpenFruit::OperationContext>();
    context->sink = sink; context->build_id = OpenFruit::NewOperationId();
    OpenFruit::OperationBinding binding(context);
    using Status = OpenFruit::SDKSelectionStatus;
    bool passed = OpenFruit::SDKSelection::Select(config, L"missing-secret-label", config_path).status == Status::NotRegistered
        && OpenFruit::SDKSelection::Select(config, L"28", config_path).status == Status::IncompleteLayout
        && OpenFruit::SDKSelection::Select(config, L"29", config_path).status == Status::InvalidPath
        && config.ios_sdk_version == L"26" && Read(config_path) == previous;
    HANDLE reader = CreateFileW(config_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (reader == INVALID_HANDLE_VALUE) return 4;
    passed = passed && OpenFruit::SDKSelection::Select(config, L"27", config_path).status == Status::PublicationFailed
        && config.ios_sdk_version == L"26" && config.sdk_path != sdk.wstring() && Read(config_path) == previous;
    const auto executable = fs::absolute(argv[1]).wstring();
    const auto blocked = OpenFruit::Win32Process::Run(executable, {executable, L"sdk", L"select", L"27"}, L"",
        {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    passed = passed && blocked.launched && blocked.exit_code == 1 && Read(config_path) == previous;
    CloseHandle(reader);
    const auto cli = OpenFruit::Win32Process::Run(executable, {executable, L"sdk", L"select", L"27"}, L"",
        {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto selected = OpenFruit::Config::Load(config_path.wstring());
    passed = passed && cli.launched && cli.exit_code == 0 && selected.ios_sdk_version == L"27"
        && selected.sdk_path == sdk.wstring() && selected.ios_sdk_paths == config.ios_sdk_paths
        && !fs::exists(root / "credentials");
    const auto selected_bytes = Read(config_path);
    const auto rejected = OpenFruit::Win32Process::Run(executable, {executable, L"sdk", L"select", L"missing"}, L"",
        {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    passed = passed && rejected.launched && rejected.exit_code == 1 && Read(config_path) == selected_bytes;
    // The CLI has changed persistent selection. A new API operation must use
    // that current snapshot rather than overwrite it with the pre-CLI selection.
    config = selected;
    passed = passed && OpenFruit::SDKSelection::Select(config, L"27", config_path).Succeeded()
        && config.ios_sdk_version == L"27" && config.sdk_path == sdk.wstring();
    bool failure_event = false;
    for (const auto& event : sink->events) {
        passed = passed && event.data.Serialize().find("missing-secret-label") == std::string::npos;
        if (event.kind == "task.completed" && event.data.GetString("status") == "publication_failed"
            && event.data.GetString("state") == "failed") failure_event = true;
    }
    passed = passed && failure_event;

    // Test SDK removal: unregistering, active lease protection, and CLI propagation.
    using RemovalStatus = OpenFruit::SDKRemovalStatus;
    passed = passed && OpenFruit::SDKRemoval::Remove(config, L"not-registered", config_path).status == RemovalStatus::NotRegistered;

    // Create an SDK to remove and verify active lease prevents removal.
    const auto sdk_removable = root / "sdk-removable";
    fs::create_directories(sdk_removable / "usr" / "lib");
    fs::create_directories(sdk_removable / "System" / "Library" / "Frameworks");
    { std::ofstream settings(sdk_removable / "SDKSettings.json"); settings << "{}"; }
    config.ios_sdk_paths[L"30"] = sdk_removable.wstring();
    config.Save(config_path.wstring());

    {
        // Hold active lease on SDK directory
        OpenFruit::SDKUsage active_lease(sdk_removable);
        passed = passed && active_lease.Held();
        const auto in_use_result = OpenFruit::SDKRemoval::Remove(config, L"30", config_path);
        passed = passed && in_use_result.status == RemovalStatus::InUse
            && fs::exists(sdk_removable)
            && config.ios_sdk_paths.count(L"30") == 1;
    }

    // After lease release, CLI removal must delete files and unregister from config.
    const auto removal_cli = OpenFruit::Win32Process::Run(executable, {executable, L"sdk", L"remove", L"30"}, L"",
        {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto post_removal = OpenFruit::Config::Load(config_path.wstring());
    passed = passed && removal_cli.launched && removal_cli.exit_code == 0
        && post_removal.ios_sdk_paths.count(L"30") == 0
        && !fs::exists(sdk_removable);

    // Also remove active selection (27) via CLI and ensure selected version is cleared.
    const auto remove_active_cli = OpenFruit::Win32Process::Run(executable, {executable, L"sdk", L"remove", L"27"}, L"",
        {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto post_active_removal = OpenFruit::Config::Load(config_path.wstring());
    passed = passed && remove_active_cli.launched && remove_active_cli.exit_code == 0
        && post_active_removal.ios_sdk_paths.count(L"27") == 0
        && post_active_removal.ios_sdk_version.empty()
        && !fs::exists(sdk);

    fs::remove_all(root); // Unique owned fixture only.
    if (!passed) std::cerr << "SDK selection and removal must validate, protect active leases and propagate through CLI.\n";
    return passed ? 0 : 1;
}
