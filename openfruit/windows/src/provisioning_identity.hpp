#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <utility>
namespace OpenFruit {
class SigningCredential;
// Expanded target request and the exact CMS bytes checked for this bundle.
// The explicit request stays separate from the profile-derived iOS signature
// inputs. Neither establishes DER authority, Apple eligibility, platform base
// entitlement injection or actual signer consumption.
struct PreparedEntitlementRequest {
    std::filesystem::path bundle_path;
    std::string bundle_identifier;
    std::string profile_cms;
    std::string requested_entitlements_xml;
    std::string profile_signature_entitlements_xml;
};
// Reverify the retained CMS and reconstruct the expected typed signature
// entitlements from the explicit request. Does not establish Apple trust/DER.
bool ValidateProvisioningSignatureEntitlements(const PreparedEntitlementRequest& prepared,
    std::string& error);
// Necessary profile/certificate binding using the exact checked CMS snapshot.
// Does not establish Apple trust, profile expiry/platform/device eligibility.
bool ValidateProvisioningSigningCertificate(const PreparedEntitlementRequest& prepared,
    const SigningCredential& credential, std::string& error,
    const std::string& code_directory_team = {});
// Prepares app/appex profile-derived identity, team, keychain and debug values
// in addition to the explicit target request. An empty entitlement path means
// the selected target declares no file; a nonempty missing path is an error.
bool PrepareProvisioningSignatureInput(const std::filesystem::path& profile,
    const std::filesystem::path& app_bundle, const std::filesystem::path& entitlements,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    PreparedEntitlementRequest& prepared, std::string& error,
    bool match_profile = false);
bool PrepareProvisioningEntitlementRequest(const std::filesystem::path& profile,
    const std::filesystem::path& app_bundle, const std::filesystem::path& entitlements,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    PreparedEntitlementRequest& prepared, std::string& error);
bool ValidateBundleSigningIdentity(const std::filesystem::path& bundle,
    const std::wstring& target_bundle_id, std::string& error);
bool MatchesProvisioningPattern(const std::string& pattern, const std::string& identity);
bool ExtractProfileBundleIdPattern(const std::filesystem::path& profile,
    std::string& prefix, std::string& pattern, std::string& error);
bool RebindBundleIdentifier(const std::filesystem::path& app_bundle,
    const std::string& new_bundle_id, std::string& error,
    std::vector<std::pair<std::filesystem::path, std::wstring>>* updated_extensions = nullptr);
// Necessary signing preflight only. Does not establish Apple trust, expiry,
// certificate eligibility, entitlement authorization or IPA signature validity.
bool ValidateProvisioningBundleIdentities(const std::filesystem::path& profile,
    const std::filesystem::path& app_bundle, std::string& error);
// Necessary allow-list check for explicit upstream target entitlements.
// Does not prepare the final signature entitlements or validate the signed IPA.
bool ValidateProvisioningRequestedEntitlements(const std::filesystem::path& profile,
    const std::filesystem::path& app_bundle, const std::filesystem::path& entitlements,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    std::string& error);
}
