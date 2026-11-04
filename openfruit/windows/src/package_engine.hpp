#pragma once

#include "sdk_manager.hpp"
#include "signing_product.hpp"
#include "win32_process.hpp"

#include <string>
#include <vector>
#include <utility>
#include <filesystem>
#include <memory>

namespace OpenFruit {
struct GitSourceView;
struct DarwinMacroProvider;
struct XcodeDependencyOptions;
class ArtifactLease;
class GeneratedSourceLifetime;

struct PackageBuildResult {
    bool success = false;
    // Actual Swift sources in built Xcode dependencies, propagated to C consumers.
    bool contains_swift_sources = false;

    std::wstring package_archive_path;
    std::wstring scratch_path;
    std::vector<std::wstring> module_include_dirs;
    // Preprocessor options from selected SwiftPM C-family module targets that
    // ClangImporter must use while parsing those modules' public headers.
    std::vector<std::wstring> clang_importer_flags;
    std::vector<std::wstring> resource_bundles;
    std::vector<SigningProduct> signing_products;
    // Physical framework slices made available through -F for module lookup.
    std::vector<std::wstring> frameworks;
    // Framework products explicitly linked by the selected Xcode target.
    std::vector<std::wstring> linked_frameworks;
    std::vector<std::wstring> dynamic_libraries;
    std::vector<std::wstring> static_libraries;
    std::vector<std::wstring> extra_link_objects;

    // Native Windows host macro executables as "<exe>#<module>".
    std::vector<std::wstring> macro_plugins;
    // Keep mutable package outputs exclusively owned through their final
    // compiler, linker and packaging consumers, including copied results.
    std::vector<std::shared_ptr<ArtifactLease>> artifact_leases;
    std::shared_ptr<GeneratedSourceLifetime> generated_source_lifetime;
    std::shared_ptr<const DarwinMacroProvider> original_macro_provider;
};

class PackageEngine {
public:
    // Empty means this build cannot establish a complete implementation input
    // closure; callers retain whole-executable invalidation in that case.
    static std::string CompilerProxyIdentity();
    // Caller owns the enclosing execution-container ArtifactLease. Existing
    // proxy bytes may remain only with matching semantic identity and verified
    // receipt hashes; missing ownership never adopts legacy files.
    static bool PrepareCompilerProxyToolchain(
        const std::filesystem::path& source_executable,
        const std::filesystem::path& toolchain_root,
        const std::filesystem::path& receipt_path,
        const std::string& semantic_identity,
        std::string& error, bool* reused = nullptr);
    // Consume failed official resolver diagnostics in an exclusively owned
    // scratch workspace; manifests and cached download bytes remain unchanged.
    static bool RecoverBinaryArtifacts(
        const std::filesystem::path& swift,
        const std::filesystem::path& scratch,
        const std::vector<std::pair<std::wstring, std::wstring>>& environment,
        const ProcessResult& failed_resolve);
    static std::vector<std::pair<std::wstring, std::wstring>> HostEnvironment(
        const std::filesystem::path& toolchain_bin);
    static PackageBuildResult BuildXcodePackages(
        const std::wstring& repo_root,
        const std::wstring& project_path,
        const SDKInfo& sdk_info,
        const std::wstring& configuration = L"debug",
        unsigned int jobs = 0,
        const GitSourceView* independent_sources = nullptr,
        const std::string& selected_target_id = {},
        const XcodeDependencyOptions* dependency_options = nullptr
    );

    static PackageBuildResult BuildSwiftPMPackage(
        const std::wstring& repo_root,
        const std::wstring& package_path,
        const SDKInfo& sdk_info,
        const std::wstring& configuration = L"debug",
        unsigned int jobs = 0
    );
};

} // namespace OpenFruit
