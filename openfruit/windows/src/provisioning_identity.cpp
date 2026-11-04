#include "provisioning_identity.hpp"
#include "signing_credential.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <plist/plist.h>
#include <fstream>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <unordered_map>
#include <algorithm>
#include <memory>
#include <string_view>
#include <iostream>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
};
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return {};
    const auto size = input.tellg();
    if (size <= 0 || size > 16 * 1024 * 1024) return {};
    std::string bytes(static_cast<std::size_t>(size), '\0');
    input.seekg(0); input.read(bytes.data(), bytes.size());
    return input ? bytes : std::string{};
}
bool Parse(const std::string& data, Plist& result) {
    return !data.empty() && data.size() <= 16 * 1024 * 1024 && plist_from_memory(data.data(), static_cast<uint32_t>(data.size()), &result.value, nullptr) == PLIST_ERR_SUCCESS
        && plist_get_node_type(result.value) == PLIST_DICT;
}
std::string String(plist_t node) {
    if (!node || plist_get_node_type(node) != PLIST_STRING) return {};
    uint64_t count = 0;
    const char* value = plist_get_string_ptr(node, &count);
    return value ? std::string(value, static_cast<std::size_t>(count)) : std::string{};
}
bool BundleIdentifier(const std::string& value) {
    if (value.empty() || value.front() == '.' || value.back() == '.' || value.find("..") != std::string::npos) return false;
    for (unsigned char c : value)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
    return true;
}
bool Matches(const std::string& pattern, const std::string& identity) {
    const auto star = pattern.find('*');
    if (star == std::string::npos) return pattern == identity;
    return star == pattern.size() - 1 && identity.starts_with(pattern.substr(0, star));
}
bool LoadSignedProfileBytes(const std::string& encoded, Plist& document, std::string& error) {
    CRYPT_VERIFY_MESSAGE_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD size = 0;
    if (encoded.empty() || encoded.size() > 16 * 1024 * 1024 || !CryptVerifyMessageSignature(&parameters, 0,
        reinterpret_cast<const BYTE*>(encoded.data()), static_cast<DWORD>(encoded.size()), nullptr, &size, nullptr)
        || !size || size > 16 * 1024 * 1024) {
        error = "Provisioning profile is not a verifiable attached signed CMS message."; return false;
    }
    std::string decoded(size, '\0');
    if (!CryptVerifyMessageSignature(&parameters, 0, reinterpret_cast<const BYTE*>(encoded.data()),
        static_cast<DWORD>(encoded.size()), reinterpret_cast<BYTE*>(decoded.data()), &size, nullptr)) {
        error = "Provisioning profile CMS signature verification failed."; return false;
    }
    decoded.resize(size);
    if (!Parse(decoded, document)) { error = "Provisioning profile payload is not a plist dictionary."; return false; }
    return true;
}
bool LoadSignedProfile(const fs::path& profile, Plist& document, std::string& error,
    std::string* verified_cms = nullptr) {
    const auto encoded = Read(profile);
    if (!LoadSignedProfileBytes(encoded, document, error)) return false;
    if (verified_cms) *verified_cms = encoded;
    return true;
}
bool ProfileIdentity(plist_t document, std::string& prefix, std::string& pattern, std::string& error) {
    const auto entitlements = plist_dict_get_item(document, "Entitlements");
    if (!entitlements || plist_get_node_type(entitlements) != PLIST_DICT) {
        error = "Provisioning profile Entitlements dictionary is missing."; return false;
    }
    const auto app_id = String(plist_dict_get_item(entitlements, "application-identifier"));
    const auto prefixes = plist_dict_get_item(document, "ApplicationIdentifierPrefix");
    if (prefixes && plist_get_node_type(prefixes) == PLIST_ARRAY) {
        for (uint32_t i = 0; i < plist_array_get_size(prefixes); ++i) {
            const auto candidate = String(plist_array_get_item(prefixes, i));
            if (BundleIdentifier(candidate) && candidate.find('.') == std::string::npos && app_id.starts_with(candidate + ".")) {
                prefix = candidate; pattern = app_id.substr(candidate.size() + 1); break;
            }
        }
    }
    if (pattern == "*" || (pattern.ends_with(".*") && BundleIdentifier(pattern.substr(0, pattern.size() - 2))) ||
        (pattern.find('*') == std::string::npos && BundleIdentifier(pattern))) return true;
    error = "Provisioning profile application identifier or prefix is invalid."; return false;
}
template <typename Visitor>
bool VisitDictionary(plist_t node, Visitor visitor) {
    plist_dict_iter iterator = nullptr;
    plist_dict_new_iter(node, &iterator);
    bool success = true;
    for (;;) {
        char* key = nullptr; plist_t value = nullptr;
        plist_dict_next_item(node, iterator, &key, &value);
        if (!value) { std::free(key); break; }
        const std::string name = key ? key : "";
        std::free(key);
        if (!visitor(name, value)) { success = false; break; }
    }
    std::free(iterator);
    return success;
}
using Settings = std::unordered_map<std::string, std::string>;
bool ExpandEntitlements(plist_t node, const Settings& settings, std::string& unresolved, unsigned depth = 0) {
    if (depth > 64) return false;
    const auto type = plist_get_node_type(node);
    if (type == PLIST_DICT) return VisitDictionary(node, [&](const std::string&, plist_t value) {
        return ExpandEntitlements(value, settings, unresolved, depth + 1);
    });
    if (type == PLIST_ARRAY) {
        for (uint32_t i = 0; i < plist_array_get_size(node); ++i)
            if (!ExpandEntitlements(plist_array_get_item(node, i), settings, unresolved, depth + 1)) return false;
    }
    if (type != PLIST_STRING) return true;
    auto value = String(node);
    if (value.find('\0') != std::string::npos) return false;
    for (unsigned pass = 0; pass < 16; ++pass) {
        std::size_t pos = 0;
        for (;;) {
            const auto parenthesis = value.find("$(", pos), brace = value.find("${", pos);
            const auto begin = std::min(parenthesis, brace);
            if (begin == std::string::npos) break;
            const auto end = value.find(begin == parenthesis ? ')' : '}', begin + 2);
            if (end == std::string::npos) return false;
            const auto name = value.substr(begin + 2, end - begin - 2);
            const auto setting = settings.find(name);
            if (setting == settings.end() || setting->second.find('\0') != std::string::npos) { unresolved = name; return false; }
            value.replace(begin, end - begin + 1, setting->second);
            pos = begin + setting->second.size();
        }
        if (value.find("$(") == std::string::npos && value.find("${") == std::string::npos) {
            plist_set_string_val(node, value.c_str()); return true;
        }
    }
    // Cycles, unknown variables and unsupported modifiers cannot silently grant
    // rights or produce unresolved signing identifiers.
    return false;
}
bool Authorized(plist_t requested, plist_t granted, unsigned depth = 0) {
    if (depth > 64 || !granted || plist_get_node_type(requested) != plist_get_node_type(granted)) return false;
    switch (plist_get_node_type(requested)) {
    case PLIST_STRING: return Matches(String(granted), String(requested));
    case PLIST_ARRAY:
        for (uint32_t i = 0; i < plist_array_get_size(requested); ++i) {
            bool allowed = false;
            for (uint32_t j = 0; j < plist_array_get_size(granted); ++j)
                allowed |= Authorized(plist_array_get_item(requested, i), plist_array_get_item(granted, j), depth + 1);
            if (!allowed) return false;
        }
        return true;
    case PLIST_DICT: return VisitDictionary(requested, [&](const std::string& key, plist_t value) {
        return Authorized(value, plist_dict_get_item(granted, key.c_str()), depth + 1);
    });
    case PLIST_BOOLEAN:
    case PLIST_INT:
    case PLIST_REAL:
    case PLIST_DATA:
    case PLIST_DATE: return plist_compare_node_value(requested, granted) != 0;
    default: return false;
    }
}
bool Serialize(plist_t value, std::string& result) {
    char* xml = nullptr; uint32_t size = 0;
    const auto status = plist_to_xml(value, &xml, &size);
    const auto release = [](char* bytes) { plist_mem_free(bytes); };
    std::unique_ptr<char, decltype(release)> owner(xml, release);
    if (status != PLIST_ERR_SUCCESS || !xml || !size) return false;
    result.assign(xml, size);
    return true;
}
bool EqualEntitlements(plist_t left, plist_t right, unsigned depth = 0) {
    if (depth > 64 || !left || !right || plist_get_node_type(left) != plist_get_node_type(right)) return false;
    switch (plist_get_node_type(left)) {
    case PLIST_DICT:
        return plist_dict_get_size(left) == plist_dict_get_size(right) &&
            VisitDictionary(left, [&](const std::string& key, plist_t value) {
                return EqualEntitlements(value, plist_dict_get_item(right, key.c_str()), depth + 1);
            });
    case PLIST_ARRAY:
        if (plist_array_get_size(left) != plist_array_get_size(right)) return false;
        for (uint32_t i = 0; i < plist_array_get_size(left); ++i)
            if (!EqualEntitlements(plist_array_get_item(left, i), plist_array_get_item(right, i), depth + 1)) return false;
        return true;
    case PLIST_STRING:
    case PLIST_BOOLEAN:
    case PLIST_INT:
    case PLIST_REAL:
    case PLIST_DATA:
    case PLIST_DATE: return plist_compare_node_value(left, right) != 0;
    default: return false;
    }
}
bool ProfileSignatureInputs(plist_t document, plist_t entitlements, const Settings& settings,
    const std::string& application_id, std::string& error) {
    const auto grants = plist_dict_get_item(document, "Entitlements");
    const auto teams = plist_dict_get_item(document, "TeamIdentifier");
    const auto team = teams && plist_get_node_type(teams) == PLIST_ARRAY && plist_array_get_size(teams) == 1
        ? String(plist_array_get_item(teams, 0)) : std::string{};
    if (team.size() != 10 || !std::all_of(team.begin(), team.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }) || String(plist_dict_get_item(grants, "com.apple.developer.team-identifier")) != team) {
        error = "Provisioning profile TeamIdentifier and team entitlement are missing, invalid or inconsistent.";
        return false;
    }
    const auto selected_team = settings.find("DEVELOPMENT_TEAM");
    if (selected_team != settings.end() && !selected_team->second.empty() && selected_team->second != team) {
        error = "Provisioning profile team does not match the selected target DEVELOPMENT_TEAM.";
        return false;
    }
    // These are profile-generated iOS values, not a copy of all enabled grants
    // and not a synthetic platform BaseEntitlements.plist.
    plist_dict_set_item(entitlements, "application-identifier", plist_new_string(application_id.c_str()));
    plist_dict_set_item(entitlements, "com.apple.developer.team-identifier", plist_new_string(team.c_str()));
    for (const auto key : {"get-task-allow", "beta-reports-active"}) {
        const auto granted = plist_dict_get_item(grants, key);
        if (!granted && std::string_view(key) == "beta-reports-active") continue;
        if (!granted || plist_get_node_type(granted) != PLIST_BOOLEAN) {
            error = "Provisioning profile has a missing or invalid boolean entitlement " + std::string(key) + ".";
            return false;
        }
        if (!plist_dict_get_item(entitlements, key)) plist_dict_set_item(entitlements, key, plist_copy(granted));
    }
    if (!plist_dict_get_item(entitlements, "keychain-access-groups")) {
        const auto groups = plist_new_array();
        plist_array_append_item(groups, plist_new_string(application_id.c_str()));
        plist_dict_set_item(entitlements, "keychain-access-groups", groups);
    }
    const auto keychain = plist_dict_get_item(entitlements, "keychain-access-groups");
    if (plist_get_node_type(keychain) != PLIST_ARRAY) {
        error = "Signature keychain-access-groups must be an array of concrete strings.";
        return false;
    }
    for (uint32_t i = 0; i < plist_array_get_size(keychain); ++i) {
        const auto group = String(plist_array_get_item(keychain, i));
        if (group.empty() || group.find('*') != std::string::npos) {
            error = "Signature keychain-access-groups must be an array of concrete strings.";
            return false;
        }
    }
    return VisitDictionary(entitlements, [&](const std::string& key, plist_t value) {
        if (Authorized(value, plist_dict_get_item(grants, key.c_str()))) return true;
        error = "Provisioning profile does not authorize derived signature entitlement " + key + ".";
        return false;
    });
}
}
bool MatchesProvisioningPattern(const std::string& pattern, const std::string& identity) {
    return Matches(pattern, identity);
}
bool ValidateProvisioningSignatureEntitlements(const PreparedEntitlementRequest& prepared, std::string& error) {
    error.clear();
    Plist document, requested, signature;
    if (!LoadSignedProfileBytes(prepared.profile_cms, document, error)) return false;
    std::string prefix, pattern;
    if (!ProfileIdentity(document.value, prefix, pattern, error)) return false;
    if (!BundleIdentifier(prepared.bundle_identifier) || !Matches(pattern, prepared.bundle_identifier)) {
        error = "Prepared signature bundle identifier is not authorized by its retained profile."; return false;
    }
    if (!Parse(prepared.requested_entitlements_xml, requested) ||
        !Parse(prepared.profile_signature_entitlements_xml, signature)) {
        error = "Prepared signature entitlement snapshots must be bounded plist dictionaries."; return false;
    }
    const auto grants = plist_dict_get_item(document.value, "Entitlements");
    if (!VisitDictionary(requested.value, [&](const std::string& key, plist_t value) {
        return Authorized(value, plist_dict_get_item(grants, key.c_str()));
    })) { error = "Retained profile does not authorize the prepared explicit entitlement request."; return false; }
    // Mutate only the reconstructed request. Never repair the supplied signature
    // dictionary: doing so would hide altered identity or removed default rights.
    if (!ProfileSignatureInputs(document.value, requested.value, {}, prefix + "." + prepared.bundle_identifier, error)) return false;
    if (!EqualEntitlements(requested.value, signature.value)) {
        error = "Prepared signature entitlements differ from the checked request and profile-derived values."; return false;
    }
    return true;
}
bool ValidateProvisioningSigningCertificate(const PreparedEntitlementRequest& prepared,
    const SigningCredential& credential, std::string& error, const std::string& code_directory_team) {
    bool authorized = false;
    OperationSpan phase("signing.certificate-preflight", JsonValue::ObjectValue(), [&] { return authorized; });
    error.clear();
    const auto& der = credential.CertificateDer();
    if (der.empty()) { error = "Signing credential has not passed native key/certificate preparation."; return false; }
    Plist document;
    if (!LoadSignedProfileBytes(prepared.profile_cms, document, error)) return false;
    std::string prefix, pattern;
    if (!ProfileIdentity(document.value, prefix, pattern, error)) return false;
    if (!BundleIdentifier(prepared.bundle_identifier) || !Matches(pattern, prepared.bundle_identifier)) {
        error = "Checked provisioning snapshot does not authorize its bound bundle identity."; return false;
    }
    if (!code_directory_team.empty()) {
        const auto teams = plist_dict_get_item(document.value, "TeamIdentifier");
        const auto grants = plist_dict_get_item(document.value, "Entitlements");
        if (!teams || plist_get_node_type(teams) != PLIST_ARRAY || plist_array_get_size(teams) != 1 ||
            String(plist_array_get_item(teams, 0)) != code_directory_team ||
            String(plist_dict_get_item(grants, "com.apple.developer.team-identifier")) != code_directory_team) {
            error = "CodeDirectory team does not match the checked provisioning profile."; return false;
        }
    }
    const auto certificates = plist_dict_get_item(document.value, "DeveloperCertificates");
    if (!certificates || plist_get_node_type(certificates) != PLIST_ARRAY || !plist_array_get_size(certificates)) {
        error = "Provisioning profile DeveloperCertificates is missing or invalid."; return false;
    }
    bool found = false;
    for (uint32_t i = 0; i < plist_array_get_size(certificates); ++i) {
        const auto cert = plist_array_get_item(certificates, i);
        if (plist_get_node_type(cert) != PLIST_DATA) {
            error = "Provisioning profile DeveloperCertificates contains a non-certificate value."; return false;
        }
        uint64_t size = 0; const auto bytes = plist_get_data_ptr(cert, &size);
        if (!bytes || !size || size > 1024 * 1024) {
            error = "Provisioning profile DeveloperCertificates contains invalid certificate data."; return false;
        }
        const auto decoded = CertCreateCertificateContext(X509_ASN_ENCODING,
            reinterpret_cast<const BYTE*>(bytes), static_cast<DWORD>(size));
        if (!decoded) { error = "Provisioning profile DeveloperCertificates contains invalid X.509 data."; return false; }
        CertFreeCertificateContext(decoded);
        found |= size == der.size() && std::equal(der.begin(), der.end(), bytes);
    }
    if (!found) {
        error = "Provisioning profile does not authorize the prepared signing certificate for bundle " + prepared.bundle_identifier + ".";
        return false;
    }
    authorized = true;
    return true;
}
bool ValidateBundleSigningIdentity(const fs::path& bundle, const std::wstring& target_bundle_id, std::string& error) {
    bool matches = false;
    OperationSpan phase("signing.target-identity", JsonValue::ObjectValue(), [&] { return matches; });
    error.clear();
    Plist info;
    if (!Parse(Read(bundle / "Info.plist"), info)) {
        error = "Bundle Info.plist is missing or invalid."; return false;
    }
    const auto identity = String(plist_dict_get_item(info.value, "CFBundleIdentifier"));
    const auto expected = Win32Process::ToNarrow(target_bundle_id);
    if (!BundleIdentifier(expected) || identity != expected) {
        error = "Embedded bundle identity does not match its selected Xcode target metadata."; return false;
    }
    matches = true; return true;
}
bool ExtractProfileBundleIdPattern(const fs::path& profile,
    std::string& prefix, std::string& pattern, std::string& error) {
    error.clear();
    Plist document;
    if (!LoadSignedProfile(profile, document, error)) return false;
    return ProfileIdentity(document.value, prefix, pattern, error);
}
bool RebindBundleIdentifier(const fs::path& app_bundle,
    const std::string& new_bundle_id, std::string& error,
    std::vector<std::pair<fs::path, std::wstring>>* updated_extensions) {
    error.clear();
    if (!BundleIdentifier(new_bundle_id)) {
        error = "Invalid target bundle identifier: " + new_bundle_id;
        return false;
    }
    Plist info;
    const auto info_path = app_bundle / "Info.plist";
    if (!Parse(Read(info_path), info) || !info.value) {
        error = "App Info.plist is missing or invalid.";
        return false;
    }
    const std::string old_bundle_id = String(plist_dict_get_item(info.value, "CFBundleIdentifier"));
    plist_dict_set_item(info.value, "CFBundleIdentifier", plist_new_string(new_bundle_id.c_str()));
    char* xml = nullptr;
    uint32_t length = 0;
    plist_to_xml(info.value, &xml, &length);
    if (!xml || !length) {
        if (xml) std::free(xml);
        error = "Failed to serialize updated Info.plist";
        return false;
    }
    std::ofstream out(info_path, std::ios::binary | std::ios::trunc);
    out.write(xml, length);
    out.close();
    std::free(xml);

    std::error_code ec;
    for (fs::recursive_directory_iterator it(app_bundle, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (it->is_directory(ec) && it->path().extension() == ".appex") {
            const auto ext_info_path = it->path() / "Info.plist";
            Plist ext_info;
            if (Parse(Read(ext_info_path), ext_info) && ext_info.value) {
                const std::string ext_id = String(plist_dict_get_item(ext_info.value, "CFBundleIdentifier"));
                std::string new_ext_id = new_bundle_id;
                if (!old_bundle_id.empty() && ext_id.starts_with(old_bundle_id + ".")) {
                    new_ext_id = new_bundle_id + ext_id.substr(old_bundle_id.size());
                } else {
                    new_ext_id = new_bundle_id + "." + it->path().stem().string();
                }
                plist_dict_set_item(ext_info.value, "CFBundleIdentifier", plist_new_string(new_ext_id.c_str()));
                char* ext_xml = nullptr;
                uint32_t ext_len = 0;
                plist_to_xml(ext_info.value, &ext_xml, &ext_len);
                if (ext_xml && ext_len) {
                    std::ofstream ext_out(ext_info_path, std::ios::binary | std::ios::trunc);
                    ext_out.write(ext_xml, ext_len);
                    ext_out.close();
                    std::free(ext_xml);
                    if (updated_extensions) {
                        updated_extensions->emplace_back(it->path(), Win32Process::ToWide(new_ext_id));
                    }
                }
            }
        }
    }
    return true;
}
bool ValidateProvisioningBundleIdentities(const fs::path& profile, const fs::path& app, std::string& error) {
    bool matches = false;
    OperationSpan phase("signing.identity-preflight", JsonValue::ObjectValue(), [&] { return matches; });
    error.clear();
    Plist document;
    if (!LoadSignedProfile(profile, document, error)) return false;
    std::string prefix, pattern;
    if (!ProfileIdentity(document.value, prefix, pattern, error)) return false;
    std::vector<fs::path> bundles{app};
    std::error_code ec;
    if (!fs::is_directory(app, ec) || ec) { error = "Application bundle is missing."; return false; }
    for (fs::recursive_directory_iterator it(app, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { error = "Cannot enumerate nested application bundles."; return false; }
        if (it->is_directory(ec) && (it->path().extension() == ".app" || it->path().extension() == ".appex")) bundles.push_back(it->path());
        if (ec) { error = "Cannot inspect nested application bundle."; return false; }
    }
    if (ec) { error = "Cannot enumerate nested application bundles."; return false; }
    for (const auto& bundle : bundles) {
        Plist info;
        if (!Parse(Read(bundle / "Info.plist"), info)) { error = "Bundle Info.plist is missing or invalid."; return false; }
        const auto identity = String(plist_dict_get_item(info.value, "CFBundleIdentifier"));
        if (!BundleIdentifier(identity)) { error = "Bundle CFBundleIdentifier is missing or invalid."; return false; }
        if (!Matches(pattern, identity)) {
            error = "Provisioning profile does not authorize bundle ID " + identity + ". Select a matching profile for each app/extension.";
            return false;
        }
    }
    matches = true;
    return true;
}
static bool PrepareProvisioningInput(const fs::path& profile, const fs::path& app,
    const fs::path& entitlements_path,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    PreparedEntitlementRequest& prepared, std::string& error, bool signature_inputs,
    bool match_profile = false) {
    bool authorized = false;
    OperationSpan phase("signing.entitlements-preflight", JsonValue::ObjectValue(), [&] { return authorized; });
    error.clear();
    prepared = {};
    Plist document, requested, info;
    std::string verified_cms;
    if (!LoadSignedProfile(profile, document, error, &verified_cms)) return false;
    if (signature_inputs && entitlements_path.empty()) {
        requested.value = plist_new_dict();
    } else if (!Parse(Read(entitlements_path), requested)) {
        error = "CODE_SIGN_ENTITLEMENTS file is missing or is not a plist dictionary."; return false;
    }
    if (!Parse(Read(app / "Info.plist"), info)) {
        error = "Bundle Info.plist is missing or invalid."; return false;
    }
    const auto identity = String(plist_dict_get_item(info.value, "CFBundleIdentifier"));
    if (!BundleIdentifier(identity)) { error = "Bundle CFBundleIdentifier is missing or invalid."; return false; }
    const auto grants = plist_dict_get_item(document.value, "Entitlements");
    if (!grants || plist_get_node_type(grants) != PLIST_DICT) {
        error = "Provisioning profile Entitlements dictionary is missing."; return false;
    }
    Settings settings;
    for (const auto& [key, value] : build_settings)
        settings[Win32Process::ToNarrow(key)] = Win32Process::ToNarrow(value);
    settings["PRODUCT_BUNDLE_IDENTIFIER"] = identity;
    // Xcode's entitlements processing also names the product identity by its
    // Info.plist key (the iCloud capability writes iCloud.$(CFBundleIdentifier)).
    settings["CFBundleIdentifier"] = identity;
    // Signing prefixes are profile facts, never arbitrary project overrides.
    settings.erase("AppIdentifierPrefix"); settings.erase("TeamIdentifierPrefix");
    if (match_profile) {
        settings.erase("DEVELOPMENT_TEAM");
    }
    std::string prefix, pattern;
    if (!ProfileIdentity(document.value, prefix, pattern, error)) return false;
    if (!Matches(pattern, identity)) {
        error = "Provisioning profile does not authorize bundle ID " + identity + "."; return false;
    }
    settings["AppIdentifierPrefix"] = prefix + ".";
    const auto teams = plist_dict_get_item(document.value, "TeamIdentifier");
    if (teams && plist_get_node_type(teams) == PLIST_ARRAY && plist_array_get_size(teams) == 1) {
        const auto team = String(plist_array_get_item(teams, 0));
        if (BundleIdentifier(team) && team.find('.') == std::string::npos) settings["TeamIdentifierPrefix"] = team + ".";
    }
    std::string unresolved;
    if (!ExpandEntitlements(requested.value, settings, unresolved)) {
        error = "CODE_SIGN_ENTITLEMENTS contains unresolved/cyclic or unsupported build-setting expressions" +
            (unresolved.empty() ? std::string(".") : " ($(" + unresolved + ") is not defined).");
        return false;
    }
    if (match_profile) {
        const auto requested_identity = plist_dict_get_item(requested.value, "application-identifier");
        if (requested_identity) {
            plist_dict_set_item(requested.value, "application-identifier", plist_new_string((prefix + "." + identity).c_str()));
        }
        std::vector<std::string> unauthorized_keys;
        VisitDictionary(requested.value, [&](const std::string& key, plist_t value) {
            if (!Authorized(value, plist_dict_get_item(grants, key.c_str()))) {
                unauthorized_keys.push_back(key);
            }
            return true;
        });
        for (const auto& key : unauthorized_keys) {
            std::cout << "OPENFRUIT signing: stripping unauthorized entitlement " << key
                      << " (not authorized by provisioning profile).\n";
            plist_dict_remove_item(requested.value, key.c_str());
        }
    } else {
        const auto requested_identity = plist_dict_get_item(requested.value, "application-identifier");
        if (requested_identity && String(requested_identity) != prefix + "." + identity) {
            error = "Requested application-identifier does not match the actual bundle identity and profile prefix."; return false;
        }
        if (!VisitDictionary(requested.value, [&](const std::string& key, plist_t value) {
            if (Authorized(value, plist_dict_get_item(grants, key.c_str()))) return true;
            error = "Provisioning profile does not authorize requested entitlement " + key + ".";
            return false;
        })) return false;
    }
    PreparedEntitlementRequest result;
    if (!Serialize(requested.value, result.requested_entitlements_xml)) {
        error = "Unable to serialize the authorized target entitlement request."; return false;
    }
    if (signature_inputs) {
        Plist signature;
        signature.value = plist_copy(requested.value);
        if (!ProfileSignatureInputs(document.value, signature.value, settings, prefix + "." + identity, error)) return false;
        if (!Serialize(signature.value, result.profile_signature_entitlements_xml)) {
            error = "Unable to serialize profile-derived signature entitlements."; return false;
        }
    }
    result.bundle_path = app;
    result.bundle_identifier = identity;
    result.profile_cms = std::move(verified_cms);
    prepared = std::move(result);
    authorized = true;
    return true;
}
bool PrepareProvisioningSignatureInput(const fs::path& profile, const fs::path& app,
    const fs::path& entitlements_path,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    PreparedEntitlementRequest& prepared, std::string& error,
    bool match_profile) {
    return PrepareProvisioningInput(profile, app, entitlements_path, build_settings, prepared, error, true, match_profile);
}
bool PrepareProvisioningEntitlementRequest(const fs::path& profile, const fs::path& app,
    const fs::path& entitlements_path,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings,
    PreparedEntitlementRequest& prepared, std::string& error) {
    return PrepareProvisioningInput(profile, app, entitlements_path, build_settings, prepared, error, false);
}
bool ValidateProvisioningRequestedEntitlements(const fs::path& profile, const fs::path& app,
    const fs::path& entitlements_path,
    const std::vector<std::pair<std::wstring, std::wstring>>& build_settings, std::string& error) {
    PreparedEntitlementRequest prepared;
    return PrepareProvisioningEntitlementRequest(profile, app, entitlements_path, build_settings, prepared, error);
}

}
