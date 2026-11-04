#include "sdk_manager.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const char* bytes) {
    std::ofstream output(path, std::ios::binary);
    output << bytes;
    output.close();
    Require(static_cast<bool>(output), "Owned SDK fixture write failed");
}
void Layout(const fs::path& sdk) {
    fs::create_directories(sdk / "usr/lib");
    fs::create_directories(sdk / "System/Library/Frameworks");
    // Layout fixtures are not validated Apple SDKs. Their intentionally distinct
    // Base SDK/deployment metadata must not replace the caller's deployment.
    Write(sdk / "SDKSettings.json", "{\"Version\":\"900.0\",\"CanonicalName\":\"iphoneos900.0\"}\n");
    Write(sdk / "Info.plist", "<plist><dict><key>MinimumOSVersion</key><string>42.0</string></dict></plist>\n");
}
struct Stamp {
    std::string digest;
    fs::file_time_type modified;
};
std::map<fs::path, Stamp> Files(const fs::path& root) {
    std::map<fs::path, Stamp> result;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        const auto digest = Sha256File(entry.path());
        Require(digest.has_value(), "Owned SDK fixture hash failed");
        result.emplace(entry.path(), Stamp{*digest, fs::last_write_time(entry.path())});
    }
    return result;
}
std::wstring Environment(const wchar_t* name) {
    const DWORD capacity = GetEnvironmentVariableW(name, nullptr, 0);
    if (!capacity) return {};
    std::wstring value(capacity, L'\0');
    const DWORD length = GetEnvironmentVariableW(name, value.data(), capacity);
    Require(length < capacity, "Environment changed during owned SDK test");
    value.resize(length);
    return value;
}
void Ready(const SDKInfo& info, const fs::path& sdk, const std::wstring& deployment) {
    Require(info.is_valid && fs::path(info.sdk_path) == sdk.lexically_normal(),
        "Inspection selected a different SDK or rejected an intact layout");
    Require(info.deployment_version == deployment && info.target_triple == L"arm64-apple-ios" + deployment,
        "Deployment target was replaced by Base SDK or Info.plist metadata");
    Require(info.vfs_overlay_path.empty() && fs::path(info.linker_overlay_path) == sdk.lexically_normal() &&
        fs::path(info.cryptex_frameworks_path) == sdk / "System/Cryptexes/OS/System/Library/Frameworks",
        "Inspection did not preserve the selected original SDK views");
}
}
int main() {
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-selected-" + NewOperationId());
    try {
        const auto first = root / "first.sdk", second = root / "second.sdk";
        Layout(first); Layout(second);
        const auto before = Files(root);
        const auto sdk_environment = Environment(L"OPENFRUIT_IOS_SDK");
        const auto home_environment = Environment(L"OPENFRUIT_HOME");
        const auto cache_environment = Environment(L"OPENFRUIT_CACHE_ROOT");
        std::string error = "prior diagnostic";
        Ready(SDKManager::InspectSelectedSDK(first, L"17.3", &error), first, L"17.3");
        Require(error.empty(), "Successful SDK inspection retained a stale error");
        Ready(SDKManager::InspectSelectedSDK(second, L"18.2"), second, L"18.2");
        Ready(SDKManager::InspectSelectedSDK(first), first, L"18.0");
        Ready(SDKManager::InspectSelectedSDK(first, L""), first, L"18.0");
        for (const auto& path : {fs::path{}, fs::path("."), fs::path("relative.sdk"), root / "absent.sdk"}) {
            error = "prior diagnostic";
            Require(!SDKManager::InspectSelectedSDK(path, L"17.3", &error).is_valid && !error.empty(),
                "Absent or relative SDK inspection fabricated a valid selection");
        }
        for (const auto* missing : {"usr/lib", "System/Library/Frameworks", "SDKSettings.json"}) {
            const auto sdk = root / (std::string("incomplete-") + std::to_string(std::string(missing).size()));
            Layout(sdk);
            fs::remove_all(sdk / missing); // Only this isolated owned SDK fixture.
            error = "prior diagnostic";
            const auto info = SDKManager::InspectSelectedSDK(sdk, L"17.3", &error);
            Require(!info.is_valid && error == "Selected SDK layout is incomplete.",
                "Incomplete SDK layout was admitted or error was not replaced");
        }
        const auto empty = root / "empty.sdk";
        fs::create_directory(empty);
        Require(!SDKManager::InspectSelectedSDK(empty, L"17.3", &error).is_valid,
            "Existing empty directory was marked as a valid SDK");
        Write(root / "not-a-directory", "owned ordinary file");
        Require(!SDKManager::InspectSelectedSDK(root / "not-a-directory", L"17.3", &error).is_valid &&
            error == "Selected SDK directory is unavailable.", "Ordinary file was accepted as an SDK directory");
        auto a = std::async(std::launch::async, [&] {
            for (unsigned i = 0; i < 32; ++i) Ready(SDKManager::InspectSelectedSDK(first, L"17.3"), first, L"17.3");
        });
        auto b = std::async(std::launch::async, [&] {
            for (unsigned i = 0; i < 32; ++i) Ready(SDKManager::InspectSelectedSDK(second, L"18.2"), second, L"18.2");
        });
        a.get(); b.get();
        Require(Environment(L"OPENFRUIT_IOS_SDK") == sdk_environment && Environment(L"OPENFRUIT_HOME") == home_environment &&
            Environment(L"OPENFRUIT_CACHE_ROOT") == cache_environment, "Selected SDK inspection modified process state");
        for (const auto& [path, stamp] : before)
            Require(Sha256File(path) == stamp.digest && fs::last_write_time(path) == stamp.modified,
                "Selected SDK inspection changed original input bytes or timestamps");
        Require(!fs::exists(root / "absent.sdk"), "Inspection created an absent SDK");
        fs::remove_all(root); // Unique owned fixtures only, after readers complete.
        std::cout << "Explicit selected SDK layout/views and concurrent request isolation passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << "; owned fixture retained: " << root << '\n';
        return 1;
    }
}
