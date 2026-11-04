#pragma once

#include "app_builder.hpp"
#include "provisioning_identity.hpp"

#include <string>
#include <vector>
#include <utility>

namespace OpenFruit {

struct PackagingSpec {
    std::wstring app_name;
    std::wstring target_name;
    std::wstring product_name;
    std::wstring executable_name;
    std::wstring module_name;
    std::wstring bundle_id;
    std::wstring display_name;

    std::wstring version = L"1.0.0";
    std::wstring build_version = L"1";
    std::wstring minimum_os_version = L"18.0";
    std::wstring icon_path;
    std::wstring app_icon_name;
    // ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS / _ALTERNATE_APPICON_NAMES.
    bool include_all_app_icons = false;
    std::vector<std::wstring> alternate_app_icons;
    std::wstring info_plist_path;
    // Evaluated from the selected Xcode target/configuration, never the profile.
    std::wstring code_sign_entitlements_path;
    std::vector<std::pair<std::wstring, std::wstring>> build_settings;

    std::vector<std::wstring> resource_bundles;
    std::vector<SigningProduct> signing_products;
    std::vector<std::wstring> resource_files;
    std::vector<std::wstring> embedded_frameworks;
    std::vector<std::wstring> embedded_dynamic_libraries;
    std::vector<std::wstring> asset_catalog_dirs;

    // Optional native signing overrides.
    std::wstring p12_path;
    std::wstring provisioning_profile_path;
    std::wstring dpapi_password_path;
    bool match_profile_bundle_id = false;
};

struct PackagingResult {
    bool success = false;
    std::wstring app_bundle_path;
    std::wstring unsigned_ipa_path;
    std::wstring signed_ipa_path;
    // CFBundleIdentifier of the signed application (after any profile rebind).
    std::wstring bundle_id;
    // Checked target requests and profile-derived iOS signature inputs for
    // every app/appex, published together after all pass. Not proof of signing.
    std::vector<PreparedEntitlementRequest> prepared_entitlement_requests;
};

class PackagerSigner {
public:
    static void ApplyDependencyProducts(PackagingSpec& spec, const PackageBuildResult& products);
    static PackagingResult PackageUnsigned(
        const std::wstring& repo_root,
        const AppBuildResult& build_result,
        const PackagingSpec& spec
    );
    static PackagingResult PackageAndSign(
        const std::wstring& repo_root,
        const AppBuildResult& build_result,
        const PackagingSpec& spec
    );

    static bool IsDynamicFramework(
        const std::filesystem::path& repo_root,
        const std::filesystem::path& framework
    );

    static bool IsDynamicMachOBinary(
        const std::filesystem::path& binary_path
    );

    static bool GenerateInfoPlist(
        const std::wstring& output_file,
        const PackagingSpec& spec
    );

private:
    static PackagingResult Package(
        const std::wstring& repo_root, const AppBuildResult& build_result,
        const PackagingSpec& spec, bool sign_requested);

    static bool CreateIpaArchive(
        const std::wstring& payload_dir,
        const std::wstring& output_ipa
    );
};

} // namespace OpenFruit
