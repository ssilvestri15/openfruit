#pragma once

#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "xcode_target_kind.hpp"
#include "generated_source_lifetime.hpp"

#include <string>
#include <vector>

namespace OpenFruit {

struct AppShellScriptPhase {
    std::wstring name;
    std::wstring shell_path;
    std::string script;
    std::vector<std::wstring> input_paths;
    std::vector<std::wstring> output_paths;
    std::size_t order = 0;
    bool after_sources = false;
};

/*
 * Universal application build specification.
 *
 * Project-specific values are discovered by UniversalProject. AppBuilder
 * consumes this plan and does not identify projects by name.
 */
struct AppBuildSpec {
    XcodeTargetKind target_kind = XcodeTargetKind::Native;
    std::string target_id;
    std::wstring app_name;
    std::wstring product_name;
    std::wstring executable_name;
    std::wstring module_name;
    std::wstring bundle_id;

    std::wstring source_root;
    std::wstring project_path;
    std::wstring bridging_header;
    std::wstring configuration = L"debug";
    std::wstring deployment_version;
    std::wstring info_plist_path;

    // Application or already-generated Swift sources/directories.
    std::vector<std::wstring> additional_sources;

    // C, Objective-C, Objective-C++, and C++ sources in the selected target.
    std::vector<std::wstring> native_sources;
    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> native_source_flags;

    // Asset catalogs belonging to the app target.
    std::vector<std::wstring> asset_catalog_dirs;

    // Selected ASSETCATALOG_COMPILER_APPICON_NAME.
    std::wstring app_icon_name;
    // ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS / _ALTERNATE_APPICON_NAMES.
    bool include_all_app_icons = false;
    std::vector<std::wstring> alternate_app_icons;

    // Mirrors Xcode's typed asset-symbol derived source generation.
    bool generate_asset_symbols = false;
    // `--preview`: link the OPENFRUIT preview agent into the application.
    bool preview_agent = false;

    // Framework names requested by the project/build plan.
    std::vector<std::wstring> frameworks;

    // Framework search paths, including Carthage/XCFramework device slices.
    std::vector<std::wstring> embedded_framework_dirs;

    // Header search paths (HEADER_SEARCH_PATHS, USER_HEADER_SEARCH_PATHS)
    std::vector<std::wstring> header_search_paths;

    // Swift include paths (SWIFT_INCLUDE_PATHS)
    std::vector<std::wstring> swift_include_paths;

    // Project-specific compiler/linker settings already translated to args.
    std::vector<std::wstring> swift_flags;
    std::vector<std::wstring> c_flags;
    std::vector<std::wstring> cxx_flags;
    std::vector<std::wstring> linker_flags;
    std::vector<std::wstring> link_libraries;
    std::vector<std::wstring> library_search_paths;

    std::string product_type = "com.apple.product-type.application";
    std::wstring products_dir;
    // Optional selected-build namespace; target UUID/owner are appended by the
    // builder so equal product names cannot share intermediates or app bundles.
    std::wstring intermediates_namespace;
    std::vector<std::wstring> public_headers;
    std::vector<std::wstring> project_headers;
    std::vector<std::wstring> resource_files;
    // Source Core Data models and the selected XCVersionGroup member.
    std::vector<std::pair<std::wstring, std::wstring>> core_data_models;
    std::vector<std::wstring> intent_definitions;
    std::vector<AppShellScriptPhase> shell_script_phases;
    std::vector<std::pair<std::wstring, std::wstring>> build_settings;

    unsigned int jobs = 0;
};

struct DiscoveredProject;

struct AppBuildResult {
    std::shared_ptr<GeneratedSourceLifetime> generated_source_lifetime;
    bool success = false;
    bool contains_swift_sources = false;
    std::wstring executable_path;
    std::wstring object_path;
    std::wstring build_root;
    std::wstring product_path;
};

class AppBuilder {
public:
    static AppBuildResult Build(
        const std::wstring& repo_root,
        const AppBuildSpec& spec,
        const SDKInfo& sdk_info,
        const PackageBuildResult& package_info
    );

    // The same planner used by execution; no products/processes are created.
    static bool ValidateTargetDependencies(const DiscoveredProject& project,
        const SDKInfo& sdk_info, const std::wstring& configuration);

    static bool BuildTargetDependencies(
        const std::wstring& repo_root,
        const DiscoveredProject& project,
        const SDKInfo& sdk_info,
        const std::wstring& configuration,
        unsigned int jobs,
        PackageBuildResult& pkg_res
    );

    static std::vector<std::wstring> ResolveArchiveLinkInputs(
        const AppBuildSpec& spec,
        const std::wstring& products_dir,
        const PackageBuildResult& package_info
    );

private:
    static bool CompileAvailabilityRuntime(
        const std::wstring& repo_root,
        const SDKInfo& sdk_info,
        std::wstring& out_version_obj
    );
};

} // namespace OpenFruit
