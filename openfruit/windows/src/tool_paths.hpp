#pragma once

#include <filesystem>
#include <string>

namespace OpenFruit {

enum class SwiftToolchainAssertions { Unspecified, Enabled, Disabled };

class ToolPaths {
public:
    static std::filesystem::path LocalHome();
    static std::filesystem::path UserStateRoot();
    static std::filesystem::path CacheRoot();
    // Digests of large, rarely changing inputs, valid while their file stat holds.
    static std::filesystem::path FileDigestCache();

    static std::filesystem::path SwiftBin(const std::filesystem::path& repo_root);
    // A managed compiler requires a publication marker and an ordinary slot;
    // copied markers never make transaction staging/backup paths selectable.
    static bool IsPublishedSwiftBin(const std::filesystem::path& swift_bin);
    // Read the upstream toolchain Identifier; directory names are not authority.
    static SwiftToolchainAssertions SwiftAssertions(const std::filesystem::path& swift_bin);
    static bool IsImportScratchPath(const std::filesystem::path& path);
    static std::filesystem::path LlvmBin(const std::filesystem::path& repo_root);
    static std::filesystem::path Git();
    static std::filesystem::path Zsign(const std::filesystem::path& repo_root);
    static std::filesystem::path Pymobiledevice3(const std::filesystem::path& repo_root);
    static std::filesystem::path Ipsw();
    static std::filesystem::path DarlingRoot(const std::filesystem::path& repo_root);
    static std::filesystem::path IosSdk(const std::filesystem::path& repo_root);
    // Read-only resolver over explicit inputs. An empty managed_home disables
    // managed fallback; neither overload creates SDK state or invokes tools.
    static std::filesystem::path IosSdk(const std::filesystem::path& managed_home,
        const std::filesystem::path& configured_sdk);
    static std::filesystem::path XcodeRoot(const std::filesystem::path& repo_root);

    static std::filesystem::path FindOnPath(const std::wstring& executable);
};

} // namespace OpenFruit
