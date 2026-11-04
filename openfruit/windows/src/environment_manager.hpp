#pragma once

#include "config.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

struct DependencyStatus {
    std::string name;
    std::string scope;
    bool available = false;
    bool required_for_build = false;
    bool auto_installable = false;
    std::filesystem::path path;
    std::string version;
    std::string detail;
};

struct BootstrapResult {
    bool build_ready = false;
    bool signing_ready = false;
    bool deploy_ready = false;
    std::vector<DependencyStatus> dependencies;
};

struct SwiftHostPlatform {
    std::filesystem::path runtime_bin;
    std::filesystem::path windows_sdk;
};

class EnvironmentManager {
public:
    // Host manifests and relocatability probes must use the same installed
    // runtime/standard library as the selected Windows Swift compiler.
    static SwiftHostPlatform ResolveSwiftHostPlatform(
        const std::filesystem::path& swift_bin);
    static bool ValidateSwiftHostToolchain(const std::filesystem::path& swift_bin);
    // Select a stable host compiler matching the Swift version bundled by the
    // chosen Xcode release. A table entry without a patch accepts the newest
    // installed patch in that major.minor series. An unlisted registered SDK may
    // require a development compiler; it must pass an actual SDK import before
    // selection, and a matching stable compiler is always preferred.
    static std::filesystem::path SelectSwiftToolchain(
        const Config& config, const std::wstring& compiler_version,
        const std::wstring& sdk_compatibility_probe = {},
        const std::wstring& deployment_target = {});
    static BootstrapResult CheckAndBootstrap(
        const std::filesystem::path& repo_root,
        Config& config,
        bool attempt_install,
        bool verbose = true
    );

    static bool EnsureManagedLayout();
    // Exercise the real SDK TAPI consumer before selecting a managed linker.
    // Upgrade only an absent provider or a proven unsupported architecture.
    static bool EnsureCompatibleLlvm(Config& config,
        const std::filesystem::path& sdk, const std::wstring& deployment_target,
        const std::wstring& architecture, bool attempt_install, std::string& error);
    // Imports a validated asset compiler bundle. With a host build environment
    // (PackageEngine::HostEnvironment for the selected toolchain) a missing
    // bundle is built from the repository's native/asset-compiler package.
    static bool EnsureAssetCompiler(const std::filesystem::path& repo_root = {},
        const std::vector<std::pair<std::wstring, std::wstring>>* build_environment = nullptr);
    static void PrintReport(const BootstrapResult& result);
};

} // namespace OpenFruit
