#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace OpenFruit {

// Cache namespace for compilation against unmodified SDK declarations.
inline constexpr char kSDKInputPolicy[] = "unmodified-sdk-v2";

struct SDKInfo {
    std::wstring sdk_path;
    std::wstring vfs_overlay_path;
    std::wstring linker_overlay_path;
    std::wstring cryptex_frameworks_path;
    std::wstring target_triple;
    std::wstring deployment_version;
    bool is_valid = false;
};

class SDKManager {
public:
    static SDKInfo DiscoverSDK(const std::wstring& repo_root, const std::wstring& preferred_version = L"18.0");
    // Inspect the already selected original SDK, without configuration,
    // environment lookup, acquisition or process execution. The caller retains
    // its SDKUsage pin through consumers; is_valid reports layout/view readiness,
    // not compiler execution or Apple provenance validation.
    static SDKInfo InspectSelectedSDK(const std::filesystem::path& selected_sdk,
        const std::wstring& deployment_version = L"18.0", std::string* error = nullptr);
    static std::wstring DetectDeploymentTarget(const std::wstring& project_or_app_path);
    static bool EnsureVFSOverlay(const std::wstring& repo_root, const std::wstring& sdk_path, std::wstring& out_vfs_path);
    static bool EnsureLinkerOverlay(const std::wstring& repo_root, const std::wstring& sdk_path, std::wstring& out_linker_path);
};

} // namespace OpenFruit
