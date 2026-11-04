#pragma once

#include "app_builder.hpp"
#include "packager_signer.hpp"
#include "xcode_project.hpp"
#include "xcode_scheme.hpp"

#include <string>
#include <vector>

namespace OpenFruit {

struct DiscoveredProject {
    bool selection_frozen = false;
    ProjectBuildAction build_action = ProjectBuildAction::LegacyProductBuild;
    std::optional<bool> build_implicit_dependencies;
    std::optional<bool> parallelize_buildables;
    std::vector<XcodeTargetDependency> selected_scheme_entries;
    std::filesystem::path selected_scheme_file;
    std::string selected_scheme_sha256;
    XcodeTargetKind target_kind = XcodeTargetKind::Native;
    std::string target_id;
    std::wstring project_name;
    std::wstring product_name;
    std::wstring module_name;
    std::wstring project_dir;
    std::wstring pbxproj_path;
    std::filesystem::path build_products_root;
    std::wstring package_swift_path;
    std::wstring primary_info_plist;
    std::wstring code_sign_entitlements_path;
    std::wstring bridging_header;

    std::wstring bundle_id;
    std::wstring display_name;
    std::wstring minimum_os_version;
    std::wstring sdk_root;
    std::wstring app_icon_path;
    std::wstring app_icon_name;
    // ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS / _ALTERNATE_APPICON_NAMES.
    bool include_all_app_icons = false;
    std::vector<std::wstring> alternate_app_icons;

    std::wstring swift_version;
    std::wstring default_actor_isolation;
    std::wstring strict_concurrency;

    std::wstring marketing_version = L"1.0.0";
    std::wstring current_project_version = L"1";

    bool generate_asset_symbols = false;

    std::vector<std::wstring> swift_sources;
    std::vector<std::wstring> c_sources;
    // Xcode per-file compiler flags, appended after the target's flags.
    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> c_source_flags;
    std::vector<std::wstring> header_search_paths;
    std::vector<std::wstring> swift_include_paths;
    std::vector<std::wstring> resource_bundles;
    std::vector<std::wstring> resource_files;
    std::vector<std::wstring> embedded_frameworks;
    std::vector<std::wstring> embedded_framework_dirs;
    std::vector<std::wstring> system_frameworks;
    std::vector<std::wstring> system_libraries;
    std::vector<std::wstring> link_libraries;
    std::vector<std::wstring> library_search_paths;
    std::vector<std::wstring> linker_flags;
    std::vector<std::wstring> xcassets_dirs;
    std::vector<std::wstring> xcstrings_files;
    std::vector<std::pair<std::wstring, std::wstring>> core_data_models;
    std::vector<std::wstring> intent_definitions;

    std::string product_type = "com.apple.product-type.application";
    std::wstring configuration = L"Release";
    std::vector<std::wstring> swift_active_compilation_conditions;
    std::vector<std::wstring> swift_flags;
    std::vector<std::wstring> c_flags;
    std::vector<std::wstring> cxx_flags;
    std::vector<std::wstring> public_headers;
    std::vector<std::wstring> project_headers;
    std::vector<XcodeTargetDependency> target_dependencies;
    std::vector<XcodeShellScriptPhase> shell_script_phases;
    std::vector<std::pair<std::wstring, std::wstring>> build_settings;

    bool is_valid = false;
};

class UniversalProject {
public:
    static DiscoveredProject Inspect(
        const std::wstring& path,
        const std::string& configuration = "Release",
        const std::filesystem::path& build_products_root = {}
    );

    static DiscoveredProject InspectTarget(
        const XcodeProject& project,
        const XcodeTarget& target,
        const std::string& configuration = "Release",
        const XcodeDependencyOptions& options = {}
    );

    static DiscoveredProject InspectSelected(
        const XcodeProject& project, const XcodeTarget& target,
        const std::string& configuration, ProjectBuildAction action,
        const std::optional<XcodeSchemeSelection>& scheme = std::nullopt);

    static AppBuildSpec ToAppBuildSpec(
        const DiscoveredProject& proj,
        unsigned int jobs = 0
    );

    static bool ResolveXcframeworkSlices(
        DiscoveredProject& proj,
        const std::wstring& target_triple,
        std::string& error
    );

    static PackagingSpec ToPackagingSpec(
        const DiscoveredProject& proj
    );
    static SigningProduct ToSigningProduct(
        const DiscoveredProject& proj, const AppBuildResult& product
    );
};

std::vector<std::wstring> ParseSearchPathsSetting(
    const std::wstring& raw,
    const std::filesystem::path& base_dir
);

} // namespace OpenFruit
