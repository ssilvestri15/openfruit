#include "sdk_manager.hpp"
#include "sdk_catalog.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

namespace OpenFruit {

std::wstring SDKManager::DetectDeploymentTarget(
    const std::wstring& project_or_app_path
) {
    fs::path root(project_or_app_path);

    const std::vector<fs::path> candidates = {
        root / "Info.plist",
        root / "Shared" / "Info.plist",
        root /
            (root.filename().wstring() +
             L"/Info.plist")
    };

    for (const auto& candidate :
         candidates) {

        if (!fs::exists(candidate)) {
            continue;
        }

        std::ifstream input(
            candidate,
            std::ios::binary
        );

        std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>()
        );

        std::smatch match;

        if (std::regex_search(
                content,
                match,
                std::regex(
                    "<key>MinimumOSVersion<\\/key>"
                    "\\s*<string>([0-9]+(?:\\.[0-9]+)?)"
                    "<\\/string>"
                )) &&
            match.size() > 1) {

            return Win32Process::ToWide(
                match[1].str()
            );
        }
    }

    return L"18.0";
}

SDKInfo SDKManager::DiscoverSDK(
    const std::wstring& repo_root,
    const std::wstring& preferred_version
) {
    // Resolve through configured or managed SDK locations only.
    const fs::path configured_sdk = ToolPaths::IosSdk(fs::path(repo_root));
    if (configured_sdk.empty()) return {};
    std::string error;
    auto info = InspectSelectedSDK(configured_sdk, preferred_version, &error);
    if (!info.is_valid) std::cerr << "OPENFRUIT SDK: " << error << std::endl;
    return info;
}

SDKInfo SDKManager::InspectSelectedSDK(const fs::path& selected_sdk,
    const std::wstring& deployment_version, std::string* error) {
    if (error) error->clear();
    SDKInfo info;
    const auto fail = [&](const char* message) {
        if (error) *error = message;
        return info;
    };
    if (selected_sdk.empty() || !selected_sdk.is_absolute())
        return fail("Selected SDK requires an absolute directory path.");
    const fs::path sdk = selected_sdk.lexically_normal();
    const auto layout = SDKCatalog::Inspect(sdk);
    if (!layout.directory) return fail("Selected SDK directory is unavailable.");
    if (!layout.Usable()) return fail("Selected SDK layout is incomplete.");
    info.sdk_path = sdk.wstring();

    info.cryptex_frameworks_path =
        (
            sdk /
            "System" /
            "Cryptexes" /
            "OS" /
            "System" /
            "Library" /
            "Frameworks"
        ).wstring();

    info.deployment_version =
        deployment_version.empty()
            ? L"18.0"
            : deployment_version;

    info.target_triple =
        L"arm64-apple-ios" +
        info.deployment_version;

    if (!EnsureVFSOverlay(
            L"",
            info.sdk_path,
            info.vfs_overlay_path)) {

        return fail("Unable to prepare the selected SDK VFS view.");
    }

    if (!EnsureLinkerOverlay(
            L"",
            info.sdk_path,
            info.linker_overlay_path)) {

        return fail("Unable to prepare the selected SDK linker view.");
    }

    info.is_valid = true;
    return info;
}

bool SDKManager::EnsureVFSOverlay(
    const std::wstring& /*repo_root*/,
    const std::wstring& sdk_path,
    std::wstring& out_vfs_path
) {
    // Compile against the original SDK. Legacy overlays enriched framework
    // headers with declarations absent from that SDK and must never be reused.
    out_vfs_path.clear();
    std::error_code ec;
    return !sdk_path.empty() && fs::is_directory(fs::path(sdk_path), ec) && !ec;
}

bool SDKManager::EnsureLinkerOverlay(
    const std::wstring& repo_root,
    const std::wstring& sdk_path,
    std::wstring& out_linker_path
) {
    // An old directory's presence does not prove faithful SDK linker inputs.
    // Always consume the selected original SDK; keep unrelated caches intact.
    out_linker_path.clear();
    const fs::path sdk(
        sdk_path
    );

    std::error_code error;
    if (sdk.empty() || !fs::is_directory(
            sdk /
            "usr" /
            "lib", error) || error) {
        return false;
    }

    out_linker_path =
        sdk.wstring();

    return true;
}

} // namespace OpenFruit
