#include "sdk_acquisition.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "json_value.hpp"
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <optional>
#include <vector>
namespace fs = std::filesystem;
struct Sink : OpenFruit::EventSink {
    std::vector<OpenFruit::OperationEvent> events;
    void Emit(OpenFruit::OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
struct ManagedHome {
    std::optional<std::wstring> previous;
    explicit ManagedHome(const fs::path& root) {
        const auto size = GetEnvironmentVariableW(L"OPENFRUIT_HOME", nullptr, 0);
        if (size) {
            std::wstring value(size, L'\0');
            value.resize(GetEnvironmentVariableW(L"OPENFRUIT_HOME", value.data(), size));
            previous = std::move(value);
        }
        SetEnvironmentVariableW(L"OPENFRUIT_HOME", root.c_str());
    }
    ~ManagedHome() { SetEnvironmentVariableW(L"OPENFRUIT_HOME", previous ? previous->c_str() : nullptr); }
};
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-acquisition-" + OpenFruit::NewOperationId());
    const auto user_state = fs::temp_directory_path() / ("OPENFRUIT-sdk-user-" + OpenFruit::NewOperationId());
    ManagedHome home(root);
    SetEnvironmentVariableW(L"OPENFRUIT_USER_STATE", user_state.c_str());
    auto sink = std::make_shared<Sink>();
    auto context = std::make_shared<OpenFruit::OperationContext>();
    context->sink = sink; context->build_id = OpenFruit::NewOperationId();
    OpenFruit::OperationBinding binding(context);
    const auto unavailable = OpenFruit::SDKAcquisition::Download("26.5", root);
    if (unavailable.Succeeded() || unavailable.status != OpenFruit::SDKAcquisitionStatus::CredentialsUnavailable
        || !unavailable.destination.empty() || fs::exists(root)) return 3;
    for (const std::string invalid : {"", "../outside", "C:/outside", ".26", "26.", "26..5", "26/token", "secret-token"}) {
        const auto result = OpenFruit::SDKAcquisition::Download(invalid, root);
        if (result.status != OpenFruit::SDKAcquisitionStatus::InvalidVersion || !result.destination.empty()
            || fs::exists(root)) return 4;
    }
    if (OpenFruit::SDKAcquisition::Download("26.5", "relative").status !=
        OpenFruit::SDKAcquisitionStatus::InvalidManagedHome) return 8;
    bool structured_failure = false;
    for (const auto& event : sink->events) {
        if (event.data.Serialize().find("secret-token") != std::string::npos) return 5;
        if (event.kind == "task.completed" && event.data.GetString("status") == "credentials_unavailable"
            && event.data.GetString("state") == "failed") structured_failure = true;
    }
    if (!structured_failure) return 6;
    const auto executable = fs::absolute(argv[1]).wstring();
    for (const auto* version : {L"26.5", L"../outside"}) {
        const auto result = OpenFruit::Win32Process::Run(executable,
            {executable, L"sdk", L"download", version}, L"", {{L"OPENFRUIT_HOME", root.wstring()}});
        if (!result.launched || result.exit_code != 1 || fs::exists(root)) {
            std::cerr << "CLI acquisition must fail without creating an installation.\n";
            return 7;
        }
    }
    const auto catalog = OpenFruit::Win32Process::Run(executable,
        {executable, L"sdk", L"catalog", L"26.5"}, L"", {{L"OPENFRUIT_USER_STATE", user_state.wstring()}});
    const auto output = OpenFruit::JsonValue::Parse(catalog.std_out);
    const bool safe_catalog = catalog.launched && catalog.exit_code == 1 && output &&
        output->GetString("status") == "credentials_unavailable" &&
        output->Get("origin_verified") && !output->Get("origin_verified")->Bool(true) &&
        output->Get("files") && output->Get("files")->IsArray() && output->Get("files")->ArrayItems().empty();
    fs::remove_all(user_state); // Unique owned user-state fixture only.
    if (!safe_catalog) return 9;
    std::cout << "SDK acquisition failure, input validation, structured diagnostics and CLI propagation pass.\n";
    return 0;
}
