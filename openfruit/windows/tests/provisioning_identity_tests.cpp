#include "provisioning_identity.hpp"
#include "signing_credential.hpp"
#include "code_directory_cms.hpp"
#include "macho_code_directory.hpp"
#include "macho_signature.hpp"
#include "entitlement_blobs.hpp"
#include "bundle_resources.hpp"
#include "tool_paths.hpp"
#include "protected_credential_store.hpp"
#include "operation_events.hpp"
#include "packager_signer.hpp"
#include "universal_project.hpp"
#include "package_engine.hpp"
#include "win32_process.hpp"
#include <plist/plist.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <map>
using namespace OpenFruit;
namespace fs = std::filesystem;
struct OwnedTestDirectory {
    const fs::path temp_root = fs::absolute(fs::temp_directory_path()).lexically_normal();
    const fs::path path = temp_root / ("OPENFRUIT-provisioning-identity-" + NewOperationId());
    ~OwnedTestDirectory() {
        // Remove only this invocation's resolved owned directory, including on
        // test failure; encrypted fixture credentials must not accumulate.
        if (path.is_absolute() && path.parent_path() == temp_root &&
            path.filename().wstring().starts_with(L"OPENFRUIT-provisioning-identity-")) {
            std::error_code ignored; fs::remove_all(path, ignored);
        }
    }
};
void Require(bool value, const char* error) { if (!value) throw std::runtime_error(error); }
void PutDirectoryWord(std::string& bytes, std::size_t offset, uint32_t value) {
    for (int i = 3; i >= 0; --i) { bytes[offset + i] = static_cast<char>(value & 255); value >>= 8; }
}
// Owned stage CodeDirectory bytes. Mach-O/page/slot generation is outside the
// CMS contract under test; no precomputed cdhash is supplied to production.
std::string OwnedDirectory(const std::string& identifier, unsigned char type = 2, const std::string& team = "OWNEDTEAM1") {
    std::string bytes(88, '\0');
    PutDirectoryWord(bytes, 0, 0xfade0c02); PutDirectoryWord(bytes, 8, 0x20400);
    PutDirectoryWord(bytes, 20, static_cast<uint32_t>(bytes.size())); bytes += identifier; bytes += '\0';
    PutDirectoryWord(bytes, 48, static_cast<uint32_t>(bytes.size())); bytes += team; bytes += '\0';
    const unsigned char size = type == 1 || type == 3 ? 20 : type == 4 ? 48 : 32;
    bytes[36] = static_cast<char>(size); bytes[37] = static_cast<char>(type); bytes[39] = 12;
    PutDirectoryWord(bytes, 16, static_cast<uint32_t>(bytes.size()));
    PutDirectoryWord(bytes, 4, static_cast<uint32_t>(bytes.size())); return bytes;
}
std::vector<BYTE> DecodeCmsValue(LPCSTR kind, const CRYPT_DATA_BLOB& blob) {
    DWORD size = 0;
    Require(CryptDecodeObjectEx(X509_ASN_ENCODING, kind, blob.pbData, blob.cbData, 0, nullptr, nullptr, &size), "unable to size CMS attribute decoding");
    std::vector<BYTE> result(size);
    Require(CryptDecodeObjectEx(X509_ASN_ENCODING, kind, blob.pbData, blob.cbData, 0, nullptr, result.data(), &size), "unable to decode CMS attribute");
    return result;
}
std::string IndependentDirectoryDigest(const std::string& bytes, const wchar_t* algorithm, DWORD size) {
    std::string digest(size, '\0');
    Require(CryptHashCertificate2(algorithm, 0, nullptr, reinterpret_cast<const BYTE*>(bytes.data()),
        static_cast<DWORD>(bytes.size()), reinterpret_cast<BYTE*>(digest.data()), &size), "independent CodeDirectory digest failed");
    digest.resize(size); return digest;
}
void CheckAppleCmsAttributes(const std::string& cms, const std::vector<std::string>& directories) {
    struct Message {
        // The encoded CMS includes ContentInfo; infer SignedData from its OID.
        // An explicit CMSG_SIGNED asks CryptoAPI to decode a bare inner object.
        HCRYPTMSG value = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, nullptr, nullptr);
        ~Message() { if (value) CryptMsgClose(value); }
    } message;
    if (!message.value || !CryptMsgUpdate(message.value, reinterpret_cast<const BYTE*>(cms.data()), static_cast<DWORD>(cms.size()), TRUE))
        throw std::runtime_error("native detached CMS decoder failed: " + std::to_string(GetLastError()));
    DWORD size = 0;
    Require(CryptMsgGetParam(message.value, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, nullptr, &size), "CMS authenticated attributes missing");
    std::vector<BYTE> storage(size);
    Require(CryptMsgGetParam(message.value, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, storage.data(), &size), "CMS authenticated attributes decoding failed");
    const auto attributes = reinterpret_cast<const CRYPT_ATTRIBUTES*>(storage.data());
    const CRYPT_ATTRIBUTE *v1 = nullptr, *v2 = nullptr;
    for (DWORD i = 0; i < attributes->cAttr; ++i) {
        const auto& attr = attributes->rgAttr[i];
        if (std::string(attr.pszObjId) == "1.2.840.113635.100.9.1") { Require(!v1, "duplicate Apple v1 attribute"); v1 = &attr; }
        if (std::string(attr.pszObjId) == "1.2.840.113635.100.9.2") { Require(!v2, "duplicate Apple v2 attribute"); v2 = &attr; }
    }
    Require(v1 && v1->cValue == 1 && v2 && v2->cValue == directories.size(), "Apple attributes contain missing or phantom CodeDirectories");
    const auto decoded_plist = DecodeCmsValue(X509_OCTET_STRING, v1->rgValue[0]);
    const auto plist_blob = reinterpret_cast<const CRYPT_DATA_BLOB*>(decoded_plist.data());
    plist_t document = nullptr;
    Require(plist_from_memory(reinterpret_cast<const char*>(plist_blob->pbData), plist_blob->cbData, &document, nullptr) == PLIST_ERR_SUCCESS,
        "Apple cdhash plist is malformed");
    struct PlistOwner { plist_t value; ~PlistOwner() { plist_free(value); } } owner{document};
    const auto hashes = plist_dict_get_item(document, "cdhashes");
    Require(hashes && plist_get_node_type(hashes) == PLIST_ARRAY && plist_array_get_size(hashes) == directories.size(), "Apple cdhash collection size incorrect");
    std::map<std::string, std::string> expected;
    for (std::size_t i = 0; i < directories.size(); ++i) {
        const auto type = static_cast<unsigned char>(directories[i][37]);
        const auto algorithm = type == 1 ? L"SHA1" : type == 4 ? L"SHA384" : L"SHA256";
        const auto oid = type == 1 ? szOID_OIWSEC_sha1 : type == 4 ? szOID_NIST_sha384 : szOID_NIST_sha256;
        const auto digest = IndependentDirectoryDigest(directories[i], algorithm, type == 1 ? 20 : type == 4 ? 48 : 32);
        expected.emplace(oid, digest);
        const auto node = plist_array_get_item(hashes, static_cast<uint32_t>(i));
        uint64_t count = 0; const auto data = plist_get_data_ptr(node, &count);
        Require(plist_get_node_type(node) == PLIST_DATA && count == 20 && std::string(data, count) == digest.substr(0, 20), "Apple v1 cdhash differs from independently hashed bytes");
    }
    for (DWORD i = 0; i < v2->cValue; ++i) {
        const auto sequence_bytes = DecodeCmsValue(X509_SEQUENCE_OF_ANY, v2->rgValue[i]);
        const auto sequence = reinterpret_cast<const CRYPT_SEQUENCE_OF_ANY*>(sequence_bytes.data());
        Require(sequence->cValue == 2, "Apple v2 value is not an OID/digest pair");
        const auto oid_bytes = DecodeCmsValue(X509_OBJECT_IDENTIFIER, sequence->rgValue[0]);
        const auto oid = *reinterpret_cast<const char* const*>(oid_bytes.data());
        const auto digest_bytes = DecodeCmsValue(X509_OCTET_STRING, sequence->rgValue[1]);
        const auto digest = reinterpret_cast<const CRYPT_DATA_BLOB*>(digest_bytes.data());
        const auto found = expected.find(oid);
        Require(found != expected.end() && found->second == std::string(reinterpret_cast<const char*>(digest->pbData), digest->cbData), "Apple v2 hash/OID differs from independently hashed CodeDirectory");
        expected.erase(found);
    }
    Require(expected.empty(), "Apple v2 omitted a CodeDirectory algorithm");
}
void File(const fs::path& path, const std::string& data) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary); out.write(data.data(), data.size());
}
std::string Bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string Info(const std::string& identity) {
    return "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>" + identity + "</string></dict></plist>";
}
struct TestSigner {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    PCCERT_CONTEXT cert = nullptr;
    ~TestSigner() {
        if (cert) CertFreeCertificateContext(cert);
        if (key) NCryptFreeObject(key);
        if (provider) NCryptFreeObject(provider);
    }
    void Initialize(int validity_offset_days = 0) {
        // Null key name means ephemeral: no user key/certificate-store changes.
        Require(NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS, "ephemeral provider failed");
        Require(NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, nullptr, 0, 0) == ERROR_SUCCESS, "ephemeral key failed");
        DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG;
        Require(NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<BYTE*>(&export_policy),
            sizeof(export_policy), 0) == ERROR_SUCCESS, "owned export policy failed");
        Require(NCryptFinalizeKey(key, 0) == ERROR_SUCCESS, "test key finalization failed");
        DWORD size = 0;
        Require(CertStrToNameW(X509_ASN_ENCODING, L"CN=OPENFRUIT Owned Identity Test", CERT_X500_NAME_STR, nullptr, nullptr, &size, nullptr), "test name size failed");
        std::vector<BYTE> name(size);
        Require(CertStrToNameW(X509_ASN_ENCODING, L"CN=OPENFRUIT Owned Identity Test", CERT_X500_NAME_STR, nullptr, name.data(), &size, nullptr), "test name failed");
        CERT_NAME_BLOB subject{size, name.data()};
        CRYPT_ALGORITHM_IDENTIFIER algorithm{const_cast<char*>(szOID_RSA_SHA256RSA), {0, nullptr}};
        FILETIME now; GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER ticks{}; ticks.LowPart = now.dwLowDateTime; ticks.HighPart = now.dwHighDateTime;
        constexpr int64_t day = 24LL * 60 * 60 * 10000000;
        ticks.QuadPart += static_cast<int64_t>(validity_offset_days) * day;
        FILETIME from{ticks.LowPart, ticks.HighPart}; SYSTEMTIME start{}, end{};
        Require(FileTimeToSystemTime(&from, &start), "owned validity start failed");
        ticks.QuadPart += 365 * day;
        FILETIME to{ticks.LowPart, ticks.HighPart};
        Require(FileTimeToSystemTime(&to, &end), "owned validity end failed");
        cert = CertCreateSelfSignCertificate(key, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO, nullptr, &algorithm, &start, &end, nullptr);
        Require(cert, "test certificate failed");
        CERT_KEY_CONTEXT context{}; context.cbSize = sizeof(context); context.hNCryptKey = key; context.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
        Require(CertSetCertificateContextProperty(cert, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &context), "test signing context failed");
    }
    std::string Sign(const std::string& xml) {
        CRYPT_SIGN_MESSAGE_PARA parameters{};
        parameters.cbSize = sizeof(parameters); parameters.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        parameters.pSigningCert = cert; parameters.HashAlgorithm.pszObjId = const_cast<char*>(szOID_NIST_sha256);
        parameters.cMsgCert = 1; parameters.rgpMsgCert = &cert;
        const BYTE* bytes = reinterpret_cast<const BYTE*>(xml.data()); DWORD size = static_cast<DWORD>(xml.size()), encoded_size = 0;
        Require(CryptSignMessage(&parameters, FALSE, 1, &bytes, &size, nullptr, &encoded_size), "test CMS size failed");
        std::string encoded(encoded_size, '\0');
        Require(CryptSignMessage(&parameters, FALSE, 1, &bytes, &size, reinterpret_cast<BYTE*>(encoded.data()), &encoded_size), "test CMS failed");
        encoded.resize(encoded_size); return encoded;
    }
    std::string Der() const { return {reinterpret_cast<const char*>(cert->pbCertEncoded), cert->cbCertEncoded}; }
    std::string P12(const std::wstring& password, bool private_key = true, PCCERT_CONTEXT other = nullptr) {
        struct Store { HCERTSTORE value = nullptr; ~Store() { if (value) CertCloseStore(value, 0); } } store;
        store.value = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
        Require(store.value, "owned PFX memory store failed");
        auto AddIdentity = [&](PCCERT_CONTEXT original) {
            struct Context { PCCERT_CONTEXT value = nullptr; ~Context() { if (value) CertFreeCertificateContext(value); } } stored;
            Require(CertAddCertificateContextToStore(store.value, original, CERT_STORE_ADD_ALWAYS, &stored.value),
                "owned PFX certificate insertion failed");
            // CertAddCertificateContextToStore deliberately omits the transient
            // key-context property. Associate this fixture's existing ephemeral
            // key with the temporary export context, without creating a key name.
            if (private_key) {
                CERT_KEY_CONTEXT context{}; DWORD size = sizeof(context);
                Require(CertGetCertificateContextProperty(original, CERT_KEY_CONTEXT_PROP_ID, &context, &size) &&
                    CertSetCertificateContextProperty(stored.value, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &context),
                    "owned PFX private-key association failed");
            }
        };
        AddIdentity(cert);
        if (other) AddIdentity(other);
        CRYPT_DATA_BLOB blob{};
        const DWORD flags = private_key ? EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY : 0;
        Require(PFXExportCertStoreEx(store.value, &blob, password.c_str(), nullptr, flags), "owned PFX export size failed");
        std::string bytes(blob.cbData, '\0'); blob.pbData = reinterpret_cast<BYTE*>(bytes.data());
        Require(PFXExportCertStoreEx(store.value, &blob, password.c_str(), nullptr, flags), "owned PFX export failed");
        bytes.resize(blob.cbData); return bytes;
    }
};
std::string Base64(const std::string& bytes) {
    DWORD size = 0;
    Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size), "owned certificate base64 size failed");
    std::string result(size, '\0');
    Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &size), "owned certificate base64 failed");
    result.resize(size); while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}
std::string Profile(const std::string& identity, const std::string& prefix = "OWNEDTEAM", const std::string& rights = "",
    bool signature_facts = true, const std::string& team = "OWNEDTEAM1") {
    std::string defaults;
    if (signature_facts) {
        if (rights.find("<key>com.apple.developer.team-identifier</key>") == std::string::npos)
            defaults += "<key>com.apple.developer.team-identifier</key><string>" + team + "</string>";
        if (rights.find("<key>get-task-allow</key>") == std::string::npos)
            defaults += "<key>get-task-allow</key><false/>";
        if (rights.find("<key>keychain-access-groups</key>") == std::string::npos)
            defaults += "<key>keychain-access-groups</key><array><string>" + prefix + ".*</string></array>";
    }
    return "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>ApplicationIdentifierPrefix</key><array><string>" + prefix +
        "</string></array>" + (signature_facts ? "<key>TeamIdentifier</key><array><string>" + team + "</string></array>" : "") +
        "<key>Entitlements</key><dict><key>application-identifier</key><string>" + identity + "</string>" + defaults + rights + "</dict></dict></plist>";
}
struct ParsedEntitlements {
    plist_t value = nullptr;
    explicit ParsedEntitlements(const std::string& xml) {
        Require(plist_from_memory(xml.data(), static_cast<uint32_t>(xml.size()), &value, nullptr) == PLIST_ERR_SUCCESS &&
            plist_get_node_type(value) == PLIST_DICT, "signature input is not a plist dictionary");
    }
    ~ParsedEntitlements() { plist_free(value); }
    std::string String(const char* key) const {
        const auto node = plist_dict_get_item(value, key);
        Require(node && plist_get_node_type(node) == PLIST_STRING,
            ("required plist string missing: " + std::string(key)).c_str());
        uint64_t size = 0; const auto bytes = plist_get_string_ptr(node, &size);
        return bytes ? std::string(bytes, static_cast<std::size_t>(size)) : "";
    }
};
std::string ProfileCertificates(const std::string& identity, const std::string& rights, const std::vector<std::string>& certs) {
    auto xml = Profile(identity, "OWNEDTEAM", rights);
    std::string certificates = "<key>DeveloperCertificates</key><array>";
    for (const auto& cert : certs) certificates += "<data>" + Base64(cert) + "</data>";
    certificates += "</array>";
    xml.insert(xml.rfind("</dict></plist>"), certificates);
    return xml;
}
struct Events final : EventSink {
    std::vector<OperationEvent> received;
    void Emit(OperationEvent event) noexcept override { received.push_back(std::move(event)); }
};
int main(int argc, char** argv) {
    // Read-only diagnostic use of the same preflight service on real artifacts.
    if (argc == 3) {
        std::string error;
        const bool match = ValidateProvisioningBundleIdentities(fs::path(argv[1]), fs::path(argv[2]), error);
        std::cout << (match ? "Bundle identities match (eligibility/IPA verification still required)." : error) << "\n";
        return match ? 0 : 1;
    }
    try {
        OwnedTestDirectory scratch;
        const auto root = scratch.path;
        const auto app = root / "Owned.app", profile = root / "owned.mobileprovision";
        File(app / "Info.plist", Info("org.owned.application"));
        TestSigner signer; signer.Initialize(); std::string error;
        auto Check = [&](const std::string& pattern, bool expected) {
            File(profile, signer.Sign(Profile(pattern)));
            Require(ValidateProvisioningBundleIdentities(profile, app, error) == expected, "profile identity decision wrong");
            Require(expected == error.empty(), "identity diagnostic missing/stale");
        };
        Check("OWNEDTEAM.org.owned.application", true);
        Check("OWNEDTEAM.org.other.application", false);
        Check("OWNEDTEAM.org.owned.*", true);
        Check("OWNEDTEAM.*", true);
        Check("OTHERTEAM.org.owned.application", false);
        Check("OWNEDTEAM.org.owned*", false);
        Check("OWNEDTEAM.org.*.application", false);
        File(app / "PlugIns" / "OwnedExtension.appex" / "Info.plist", Info("org.owned.application.extension"));
        Check("OWNEDTEAM.org.owned.application", false);
        Check("OWNEDTEAM.org.owned.*", true);
        File(app / "PlugIns" / "OwnedExtension.appex" / "Info.plist", Info("org.other.extension"));
        Check("OWNEDTEAM.org.owned.*", false);
        File(profile, Profile("OWNEDTEAM.*"));
        Require(!ValidateProvisioningBundleIdentities(profile, app, error), "unsigned XML accepted as provisioning CMS");
        auto corrupted = signer.Sign(Profile("OWNEDTEAM.*"));
        const auto content = corrupted.find("OWNEDTEAM.*");
        Require(content != std::string::npos, "CMS fixture content not found");
        corrupted[content] = 'X'; File(profile, corrupted);
        Require(!ValidateProvisioningBundleIdentities(profile, app, error), "tampered profile accepted");

        // Propagation to the actual packaging/signing boundary. The bundle ID
        // must be discovered from pbxproj/xcconfig and assembled by production
        // packaging, never supplied as a resolved expected value by the test.
        const auto discovered = UniversalProject::Inspect(
            fs::path(OPENFRUIT_SIGNING_PROJECT_FIXTURE).wstring(), "Debug");
        Require(discovered.is_valid, "owned project metadata discovery failed");
        auto packaging = UniversalProject::ToPackagingSpec(discovered);
        const auto original_entitlements = Bytes(fs::path(packaging.code_sign_entitlements_path));
        packaging.provisioning_profile_path = profile.wstring();
        File(profile, signer.Sign(Profile("OWNEDTEAM.org.unrelated.application")));
        AppBuildResult product;
        product.success = true;
        product.build_root = (root / "package-stage").wstring();
        product.executable_path = (root / "linked-product-sentinel").wstring();
        // The sentinel only satisfies this stage's input-file precondition;
        // executable generation/Mach-O validity are outside this identity test.
        File(fs::path(product.executable_path), "owned stage input sentinel");
        auto sink = std::make_shared<Events>();
        auto context = std::make_shared<OperationContext>();
        context->sink = sink; context->build_id = NewOperationId();
        std::ostringstream diagnostics;
        auto* old = std::cerr.rdbuf(diagnostics.rdbuf());
        PackagingResult packaged;
        {
            OperationBinding binding(context);
            packaged = PackagerSigner::PackageAndSign(root.wstring(), product, packaging);
        }
        std::cerr.rdbuf(old);
        Require(!packaged.success && diagnostics.str().find("does not authorize bundle ID") != std::string::npos,
            "packaging did not reject profile against derived bundle identity");
        bool failure = false;
        for (const auto& event : sink->received) {
            Require(event.kind != "process.started", "packaging launched a process before rejecting identity");
            failure |= event.kind == "task.completed" && event.data.GetString("name") == "signing.identity-preflight"
                && event.data.GetString("state") == "failed";
        }
        Require(failure, "packaging identity rejection lost structured failure event");
        Require(!fs::exists(packaged.signed_ipa_path), "rejected signing published an IPA");

        // Correct bundle identity alone is insufficient. The real packaging
        // consumer must receive CODE_SIGN_ENTITLEMENTS and its bindings from
        // project/configuration metadata, with no resolved path/group injected.
        Require(!packaging.code_sign_entitlements_path.empty(), "CODE_SIGN_ENTITLEMENTS was lost during discovery/propagation");
        File(profile, signer.Sign(Profile("OWNEDTEAM.*")));
        sink->received.clear(); diagnostics.str(""); diagnostics.clear();
        old = std::cerr.rdbuf(diagnostics.rdbuf());
        {
            OperationBinding binding(context);
            packaged = PackagerSigner::PackageAndSign(root.wstring(), product, packaging);
        }
        std::cerr.rdbuf(old);
        Require(!packaged.success && diagnostics.str().find("does not authorize requested entitlement com.apple.security.application-groups") != std::string::npos,
            "packaging discarded upstream capabilities despite matching bundle ID");
        failure = false;
        for (const auto& event : sink->received) {
            Require(event.kind != "process.started", "unauthorized entitlement reached signer process");
            failure |= event.kind == "task.completed" && event.data.GetString("name") == "signing.entitlements-preflight"
                && event.data.GetString("state") == "failed";
        }
        Require(failure, "entitlement authorization failure event missing");
        Require(!fs::exists(packaged.signed_ipa_path), "unauthorized capabilities published an IPA");
        const auto rights = "<key>com.apple.security.application-groups</key><array><string>group.org.OPENFRUIT.signing-identity-probe</string><string>group.org.other</string></array>";
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", rights)));
        Require(ValidateProvisioningRequestedEntitlements(profile, fs::path(packaged.app_bundle_path),
            fs::path(packaging.code_sign_entitlements_path), packaging.build_settings, error), "derived requested entitlement subset was not authorized");

        // Extension metadata follows the same producer/consumer services used
        // by AppBuilder and the CLI. Physical stage inputs are owned sentinels;
        // compiler output generation remains outside this propagation test.
        const auto project = XcodeProject::Load(fs::path(OPENFRUIT_SIGNING_PROJECT_FIXTURE));
        Require(project.has_value(), "extension project load failed");
        const auto target = project->FindTarget("OwnedExtension");
        Require(target.has_value(), "extension target discovery failed");
        const auto extension = UniversalProject::InspectTarget(*project, *target, "Debug");
        Require(extension.is_valid, "extension settings discovery failed");
        AppBuildResult extension_product;
        extension_product.success = true;
        extension_product.product_path = (root / "dependency-products" / (extension.product_name + L".appex")).wstring();
        const auto fixture_info = fs::path(OPENFRUIT_SIGNING_PROJECT_FIXTURE) /
            (extension.product_name + L".appex") / "Info.plist";
        const auto extension_info = Bytes(fixture_info);
        Require(!extension_info.empty(), "extension stage input is missing");
        File(fs::path(extension_product.product_path) / "Info.plist", extension_info);
        const auto extension_template = Bytes(fs::path(extension.code_sign_entitlements_path));
        PackageBuildResult dependencies;
        dependencies.resource_bundles.push_back(extension_product.product_path);
        dependencies.signing_products.push_back(UniversalProject::ToSigningProduct(extension, extension_product));
        const auto& metadata = dependencies.signing_products.front();
        Require(metadata.target_id == extension.target_id && metadata.project_file == extension.pbxproj_path &&
            metadata.configuration == extension.configuration && metadata.bundle_id == extension.bundle_id &&
            metadata.entitlements_path == extension.code_sign_entitlements_path &&
            metadata.entitlements_path != packaging.code_sign_entitlements_path,
            "extension target identity/settings were lost or replaced by container settings");
        auto with_extension = packaging;
        PackagerSigner::ApplyDependencyProducts(with_extension, dependencies);
        Require(with_extension.signing_products.size() == 1 && with_extension.resource_bundles.size() == 1,
            "CLI dependency-product propagation discarded extension metadata/products");
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", rights)));
        auto RejectExtension = [&](PackagingSpec spec, const char* diagnostic, const char* stage) {
            auto input = product;
            input.build_root = (root / stage).wstring();
            sink->received.clear(); diagnostics.str(""); diagnostics.clear();
            auto* previous = std::cerr.rdbuf(diagnostics.rdbuf());
            PackagingResult result;
            { OperationBinding binding(context); result = PackagerSigner::PackageAndSign(root.wstring(), input, spec); }
            std::cerr.rdbuf(previous);
            Require(!result.success && diagnostics.str().find(diagnostic) != std::string::npos,
                "extension preflight failed at the wrong boundary or accepted invalid input");
            for (const auto& event : sink->received)
                Require(event.kind != "process.started", "invalid extension reached signer process");
            Require(!fs::exists(result.signed_ipa_path), "invalid extension published an IPA");
            return result;
        };
        const auto rejected_extension = RejectExtension(with_extension,
            "does not authorize requested entitlement com.apple.security.application-groups", "extension-rights");
        failure = false;
        for (const auto& event : sink->received)
            failure |= event.kind == "task.completed" && event.data.GetString("name") == "signing.entitlements-preflight"
                && event.data.GetString("state") == "failed";
        Require(failure, "extension entitlement failure event was lost");
        Require(Bytes(fs::path(rejected_extension.app_bundle_path) / "PlugIns" /
            fs::path(extension_product.product_path).filename() / "Info.plist") == extension_info,
            "packaging rewrote extension Info.plist to manufacture a matching identity");
        auto missing_metadata = with_extension;
        missing_metadata.signing_products.clear();
        RejectExtension(missing_metadata, "extension target signing metadata is missing", "extension-missing");
        auto missing_product = with_extension;
        missing_product.resource_bundles.front() = (root / "absent.appex").wstring();
        RejectExtension(missing_product, "declared extension product is missing", "extension-absent");
        auto resource_bypass = packaging;
        resource_bypass.resource_files.push_back(extension_product.product_path);
        RejectExtension(resource_bypass, "nested application signing metadata is missing", "extension-resource-bypass");
        auto ambiguous = with_extension;
        ambiguous.signing_products.push_back(ambiguous.signing_products.front());
        RejectExtension(ambiguous, "ambiguous extension signing metadata", "extension-ambiguous");
        auto incorrect_identity = with_extension;
        incorrect_identity.signing_products.front().bundle_id = discovered.bundle_id;
        RejectExtension(incorrect_identity, "does not match its selected Xcode target metadata", "extension-wrong-target");
        auto colliding_product = extension_product;
        colliding_product.product_path = (root / "other-products" /
            fs::path(extension_product.product_path).filename()).wstring();
        File(fs::path(colliding_product.product_path) / "Info.plist", extension_info);
        auto collision = with_extension;
        collision.resource_bundles.push_back(colliding_product.product_path);
        collision.signing_products.push_back(UniversalProject::ToSigningProduct(extension, colliding_product));
        RejectExtension(collision, "extension products collide", "extension-collision");
        Require(Bytes(fs::path(extension.code_sign_entitlements_path)) == extension_template &&
            Bytes(fixture_info) == extension_info, "extension preflight modified upstream stage/template inputs");

        // Successful request preparation must retain each bundle's resolved
        // data and exactly the CMS snapshot whose allow-list was checked.
        const auto all_rights = "<key>com.apple.security.application-groups</key><array>"
            "<string>group.org.OPENFRUIT.signing-identity-probe</string>"
            "<string>group.org.OPENFRUIT.extension-only</string>"
            "<string>group.org.extra-grant</string></array>";
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", all_rights)));
        auto prepare_input = product;
        prepare_input.build_root = (root / "prepared-requests").wstring();
        sink->received.clear(); diagnostics.str(""); diagnostics.clear();
        old = std::cerr.rdbuf(diagnostics.rdbuf());
        { OperationBinding binding(context); packaged = PackagerSigner::PackageAndSign(root.wstring(), prepare_input, with_extension); }
        std::cerr.rdbuf(old);
        Require(!packaged.success && packaged.prepared_entitlement_requests.size() == 2,
            "packaging discarded authorized target request data or claimed signing success without credentials");
        const auto checked_profile = Bytes(profile);
        auto RequestGroup = [&](const PreparedEntitlementRequest& request) {
            Require(request.profile_cms == checked_profile, "prepared request is detached from verified profile snapshot");
            plist_t parsed = nullptr;
            Require(plist_from_memory(request.requested_entitlements_xml.data(),
                static_cast<uint32_t>(request.requested_entitlements_xml.size()), &parsed, nullptr) == PLIST_ERR_SUCCESS,
                "prepared request XML is invalid");
            const auto group = plist_array_get_item(plist_dict_get_item(parsed, "com.apple.security.application-groups"), 0);
            uint64_t count = 0;
            const auto value = plist_get_string_ptr(group, &count);
            const std::string actual = value ? std::string(value, static_cast<std::size_t>(count)) : "";
            plist_free(parsed);
            Require(request.requested_entitlements_xml.find("$(") == std::string::npos &&
                request.requested_entitlements_xml.find("group.org.extra-grant") == std::string::npos,
                "prepared request retained unresolved expressions or substituted all profile grants");
            return actual;
        };
        const auto& root_request = packaged.prepared_entitlement_requests[0];
        const auto& child_request = packaged.prepared_entitlement_requests[1];
        Require(root_request.bundle_identifier == Win32Process::ToNarrow(discovered.bundle_id) &&
            child_request.bundle_identifier == Win32Process::ToNarrow(extension.bundle_id) &&
            root_request.bundle_path != child_request.bundle_path && RequestGroup(root_request) != RequestGroup(child_request),
            "prepared root and extension requests were mixed or lost their physical owner");
        auto CheckProfileInputs = [&](const PreparedEntitlementRequest& input) {
            ParsedEntitlements signature(input.profile_signature_entitlements_xml);
            Require(signature.String("application-identifier") == "OWNEDTEAM." + input.bundle_identifier &&
                signature.String("com.apple.developer.team-identifier") == "OWNEDTEAM1",
                "signature inputs lost per-bundle identity or confused App ID prefix and team");
            const auto groups = plist_dict_get_item(signature.value, "keychain-access-groups");
            Require(groups && plist_get_node_type(groups) == PLIST_ARRAY && plist_array_get_size(groups) == 1,
                "default keychain groups were copied wholesale from the profile");
            uint64_t size = 0;
            const auto group = plist_get_string_ptr(plist_array_get_item(groups, 0), &size);
            Require(group && std::string(group, static_cast<std::size_t>(size)) == "OWNEDTEAM." + input.bundle_identifier,
                "default keychain group belongs to another bundle or retained a wildcard");
            const auto task = plist_dict_get_item(signature.value, "get-task-allow");
            Require(task && plist_get_node_type(task) == PLIST_BOOLEAN, "profile debug value was not propagated");
            uint8_t debug = 1; plist_get_bool_val(task, &debug);
            Require(debug == 0 && !plist_dict_get_item(signature.value, "beta-reports-active"),
                "target Debug/Release configuration invented profile-controlled debugger/TestFlight rights");
            Require(input.profile_cms == checked_profile && input.profile_signature_entitlements_xml.find("group.org.extra-grant") == std::string::npos,
                "profile signature inputs lost their checked snapshot or copied unused capabilities");
        };
        CheckProfileInputs(root_request);
        CheckProfileInputs(child_request);
        ParsedEntitlements root_signature(root_request.profile_signature_entitlements_xml);
        ParsedEntitlements child_signature(child_request.profile_signature_entitlements_xml);
        Require(plist_compare_node_value(plist_array_get_item(plist_dict_get_item(root_signature.value, "com.apple.security.application-groups"), 0),
            plist_array_get_item(plist_dict_get_item(child_signature.value, "com.apple.security.application-groups"), 0)) == 0,
            "profile-derived payload replaced extension App Group with container rights");

        // A real selected configuration with no entitlement file must still
        // prepare distinct root/extension profile inputs. No path/settings are
        // removed or pre-resolved by this test.
        const auto plain_root = UniversalProject::Inspect(fs::path(OPENFRUIT_SIGNING_PROJECT_FIXTURE).wstring(), "Release");
        const auto plain_child = UniversalProject::InspectTarget(*project, *target, "Release");
        Require(plain_root.is_valid && plain_child.is_valid && plain_root.code_sign_entitlements_path.empty() &&
            plain_child.code_sign_entitlements_path.empty(), "fixture no-file configuration was not discovered");
        auto plain_spec = UniversalProject::ToPackagingSpec(plain_root);
        plain_spec.provisioning_profile_path = profile.wstring();
        PackageBuildResult plain_dependencies;
        plain_dependencies.resource_bundles.push_back(extension_product.product_path);
        plain_dependencies.signing_products.push_back(UniversalProject::ToSigningProduct(plain_child, extension_product));
        PackagerSigner::ApplyDependencyProducts(plain_spec, plain_dependencies);
        prepare_input.build_root = (root / "profile-inputs-no-file").wstring();
        old = std::cerr.rdbuf(diagnostics.rdbuf());
        PackagingResult plain_packaged;
        { OperationBinding binding(context); plain_packaged = PackagerSigner::PackageAndSign(root.wstring(), prepare_input, plain_spec); }
        std::cerr.rdbuf(old);
        Require(!plain_packaged.success && plain_packaged.prepared_entitlement_requests.size() == 2,
            "packaging skipped a target without CODE_SIGN_ENTITLEMENTS or bypassed signing credentials");
        for (const auto& input : plain_packaged.prepared_entitlement_requests) {
            CheckProfileInputs(input);
            ParsedEntitlements explicit_request(input.requested_entitlements_xml);
            Require(plist_dict_get_size(explicit_request.value) == 0 &&
                input.profile_signature_entitlements_xml.find("com.apple.security.application-groups") == std::string::npos,
                "no-file target borrowed unrequested capabilities from its profile or container");
        }
        for (const auto& event : sink->received)
            Require(event.kind != "process.started", "no-file target preparation bypassed missing credentials");
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", all_rights, true, "OTHERTEAM1")));
        const auto wrong_team = RejectExtension(with_extension, "does not match the selected target DEVELOPMENT_TEAM", "profile-wrong-team");
        Require(wrong_team.prepared_entitlement_requests.empty(), "team mismatch exposed partially authorized signature inputs");
        for (const auto& event : sink->received)
            Require(event.kind != "process.started", "request preparation bypassed missing signing credentials");
        Require(rejected_extension.prepared_entitlement_requests.empty(),
            "failed child preflight exposed a partial request plan");
        PreparedEntitlementRequest stale = root_request;
        File(profile, signer.Sign(Profile("OWNEDTEAM.org.unrelated", "OWNEDTEAM", all_rights)));
        Require(!PrepareProvisioningEntitlementRequest(profile, root_request.bundle_path,
            fs::path(packaging.code_sign_entitlements_path), packaging.build_settings, stale, error) &&
            stale.profile_cms.empty() && stale.requested_entitlements_xml.empty() && stale.bundle_identifier.empty(),
            "request preparation accepted a different profile identity or retained stale authorization data");
        stale = root_request;
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", all_rights, false)));
        Require(!PrepareProvisioningSignatureInput(profile, root_request.bundle_path,
            fs::path(packaging.code_sign_entitlements_path), packaging.build_settings, stale, error) &&
            stale.profile_cms.empty() && stale.profile_signature_entitlements_xml.empty(),
            "signature preparation accepted missing profile facts or retained a stale signing payload");
        Require(Bytes(fs::path(packaging.code_sign_entitlements_path)) == original_entitlements &&
            Bytes(fs::path(extension.code_sign_entitlements_path)) == extension_template,
            "request serialization modified original entitlement templates");

        // Native credential producer -> verified profile snapshot consumer.
        // All keys/certificates are ephemeral owned fixtures. PFX export uses
        // a temporary memory store, never the user's certificate/key stores.
        const std::wstring owned_password = L"OPENFRUIT owned PFX test \u00e8";
        const auto owned_p12 = root / "owned-signing.p12";
        const auto protected_password = root / "owned-password.dpapi";
        File(owned_p12, signer.P12(owned_password));
        Require(ProtectedCredentialStore::Write(protected_password, owned_password, CredentialPurpose::SigningPassword),
            "owned DPAPI password preparation failed");
        SigningCredential credential;
        const auto credential_ready = PrepareSigningCredential(owned_p12, owned_password, credential, error);
        Require(credential_ready, error.c_str());
        Require(credential.CertificateDer() == signer.Der(), "prepared credential certificate changed");
        File(profile, signer.Sign(ProfileCertificates("OWNEDTEAM.*", all_rights, {signer.Der()})));
        PreparedEntitlementRequest with_certificate;
        Require(PrepareProvisioningSignatureInput(profile, root_request.bundle_path,
            fs::path(packaging.code_sign_entitlements_path), packaging.build_settings, with_certificate, error) &&
            ValidateProvisioningSigningCertificate(with_certificate, credential, error),
            "prepared PFX certificate was not bound to the profile's authorized DER identity");
        Require(ValidateProvisioningSignatureEntitlements(with_certificate, error), error.c_str());
        std::vector<PreparedEntitlementRequest> altered_signature_inputs;
        for (int mutation = 0; mutation < 6; ++mutation) {
            auto changed = with_certificate;
            ParsedEntitlements xml(changed.profile_signature_entitlements_xml);
            if (mutation == 0) plist_dict_set_item(xml.value, "application-identifier", plist_new_string("OWNEDTEAM.org.other"));
            if (mutation == 1) plist_dict_remove_item(xml.value, "keychain-access-groups");
            if (mutation == 2) plist_dict_set_item(xml.value, "get-task-allow", plist_new_uint(1));
            if (mutation == 3) plist_dict_set_item(xml.value, "ungranted.entitlement", plist_new_bool(1));
            if (mutation == 4) plist_array_append_item(plist_dict_get_item(xml.value, "com.apple.security.application-groups"),
                plist_new_string("group.org.extra-grant"));
            if (mutation == 5) plist_dict_set_item(xml.value, "com.apple.developer.team-identifier", plist_new_string("OTHERTEAM1"));
            char* bytes = nullptr; uint32_t size = 0;
            Require(plist_to_xml(xml.value, &bytes, &size) == PLIST_ERR_SUCCESS && bytes, "unable to serialize owned entitlement mutation");
            changed.profile_signature_entitlements_xml.assign(bytes, size); plist_mem_free(bytes);
            Require(!ValidateProvisioningSignatureEntitlements(changed, error) && !error.empty(),
                "signature validation accepted altered identity/default/type or an unrequested profile grant");
            altered_signature_inputs.push_back(std::move(changed));
        }
        auto changed_request = with_certificate;
        changed_request.requested_entitlements_xml = "<plist version=\"1.0\"><dict><key>ungranted.entitlement</key><true/></dict></plist>";
        Require(!ValidateProvisioningSignatureEntitlements(changed_request, error), "mutated explicit request bypassed profile authorization");
        File(profile, "mutated live profile path");
        Require(ValidateProvisioningSigningCertificate(with_certificate, credential, error),
            "certificate authorization reread a mutable profile path instead of checked CMS bytes");
        SigningCredential moved(std::move(credential));
        Require(credential.CertificateDer().empty() && ValidateProvisioningSigningCertificate(with_certificate, moved, error),
            "moving the credential lost its ephemeral identity or retained stale output");
        credential = std::move(moved);
        // CMS provider contract: content/DER attributes are owned stage inputs.
        // This does not test a Mach-O/CodeDirectory producer or an IPA signature.
        File(owned_p12, "replaced after native credential preparation");
        const std::string cms_content = "owned detached signature content";
        const std::string attribute_value("\x04\x03" "abc", 5);
        const std::vector<CmsAuthenticatedAttribute> cms_attributes{
            {"1.2.3.4", {attribute_value}}};
        std::string native_cms;
        Require(credential.SignDetachedCms(cms_content, cms_attributes, native_cms, error), error.c_str());
        auto VerifyNativeCms = [&](const std::string& message, const std::string& content) {
            CRYPT_VERIFY_MESSAGE_PARA verify{};
            verify.cbSize = sizeof(verify);
            verify.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
            const BYTE* bytes = reinterpret_cast<const BYTE*>(content.data());
            DWORD size = static_cast<DWORD>(content.size());
            PCCERT_CONTEXT certificate = nullptr;
            const bool valid = CryptVerifyDetachedMessageSignature(&verify, 0,
                reinterpret_cast<const BYTE*>(message.data()), static_cast<DWORD>(message.size()),
                1, &bytes, &size, &certificate) != FALSE;
            const bool identity = certificate && certificate->cbCertEncoded == signer.Der().size() &&
                std::string(reinterpret_cast<const char*>(certificate->pbCertEncoded), certificate->cbCertEncoded) == signer.Der();
            if (certificate) CertFreeCertificateContext(certificate);
            return valid && identity;
        };
        Require(VerifyNativeCms(native_cms, cms_content), "native CMS failed independent verification or changed certificate");
        Require(!VerifyNativeCms(native_cms, cms_content + "modified"), "native CMS accepted altered detached content");
        const auto sealed_attribute = native_cms.find(attribute_value);
        Require(sealed_attribute != std::string::npos, "native CMS lost its supplied authenticated attribute");
        auto modified_cms = native_cms;
        modified_cms[sealed_attribute + 2] = 'z';
        Require(!VerifyNativeCms(modified_cms, cms_content), "native CMS did not authenticate supplied attribute values");
        Require(ValidateProvisioningSigningCertificate(with_certificate, credential, error, "OWNEDTEAM1") &&
            !ValidateProvisioningSigningCertificate(with_certificate, credential, error, "OTHERTEAM1"),
            "CodeDirectory team binding ignored the checked profile's team");
        auto RejectCms = [&](const SigningCredential& identity, const std::string& content,
                             const std::vector<CmsAuthenticatedAttribute>& attrs) {
            native_cms = "stale output";
            Require(!identity.SignDetachedCms(content, attrs, native_cms, error) && native_cms.empty() && !error.empty(),
                "invalid native CMS input succeeded or retained stale signature output");
        };
        SigningCredential empty_credential;
        RejectCms(empty_credential, cms_content, cms_attributes);
        RejectCms(credential, "", cms_attributes);
        RejectCms(credential, cms_content, {{"1.2.3", {} }});
        RejectCms(credential, cms_content, {{"1.2.3", {""} }});
        RejectCms(credential, cms_content, {{"1.2.3", {attribute_value}}, {"1.2.3", {attribute_value}}});
        RejectCms(credential, cms_content, {{szOID_RSA_messageDigest, {attribute_value}}});
        RejectCms(credential, cms_content, {{szOID_RSA_contentType, {attribute_value}}});
        RejectCms(credential, cms_content, {{"1.2.3", {"not DER"}}});
        RejectCms(credential, cms_content, {{"1.2.3", {std::string("\x04\x80\0\0", 4)}}});
        RejectCms(credential, cms_content, {{"1.2.3", {std::string("\x04\x81\x03" "abc", 6)}}});
        RejectCms(credential, cms_content, {{"1.2.3", {attribute_value + "trailing"}}});
        Require(credential.SignDetachedCms(cms_content, {}, native_cms, error) && VerifyNativeCms(native_cms, cms_content),
            "native CMS without supplied authenticated attributes failed");
        const auto primary_directory = OwnedDirectory(with_certificate.bundle_identifier);
        const std::vector<std::string> actual_directories{primary_directory,
            OwnedDirectory(with_certificate.bundle_identifier, 1), OwnedDirectory(with_certificate.bundle_identifier, 4)};
        Require(BuildProvisioningCodeDirectoryCms(with_certificate, credential, actual_directories, native_cms, error), error.c_str());
        Require(VerifyNativeCms(native_cms, primary_directory), "CodeDirectory CMS is not detached from the primary blob");
        CheckAppleCmsAttributes(native_cms, actual_directories);
        Require(!VerifyNativeCms(native_cms, actual_directories[1]), "CodeDirectory CMS accepted the alternate as primary content");
        for (const unsigned char algorithm : {1, 2, 3, 4}) {
            const std::vector<std::string> only{OwnedDirectory(with_certificate.bundle_identifier, algorithm)};
            Require(BuildProvisioningCodeDirectoryCms(with_certificate, credential, only, native_cms, error), error.c_str());
            Require(VerifyNativeCms(native_cms, only[0]), "single CodeDirectory signature failed verification");
            CheckAppleCmsAttributes(native_cms, only);
        }
        auto bound_child = child_request;
        bound_child.profile_cms = with_certificate.profile_cms;
        CodeDirectorySpecialSlots root_entitlement_blobs, child_entitlement_blobs;
        Require(BuildProvisioningEntitlementBlobs(with_certificate, root_entitlement_blobs, error) &&
            BuildProvisioningEntitlementBlobs(bound_child, child_entitlement_blobs, error), error.c_str());
        Require(root_entitlement_blobs.at(5) != child_entitlement_blobs.at(5) && root_entitlement_blobs.at(7) != child_entitlement_blobs.at(7),
            "distinct discovered root/extension requests produced identical entitlement blobs");
        Require(!ValidateProvisioningEntitlementBlobs(bound_child, root_entitlement_blobs, error), "root entitlement pair accepted for child");
        auto stale_entitlement_blobs = root_entitlement_blobs;
        Require(!BuildProvisioningEntitlementBlobs(altered_signature_inputs.front(), stale_entitlement_blobs, error) && stale_entitlement_blobs.empty(),
            "failed entitlement producer published stale/partial signature inputs");
        File(profile, signer.Sign(ProfileCertificates("OWNEDTEAM.*", std::string(all_rights) + "<key>get-task-allow</key><true/>", {signer.Der()})));
        PreparedEntitlementRequest debug_signature_input;
        Require(PrepareProvisioningSignatureInput(profile, root_request.bundle_path,
            fs::path(packaging.code_sign_entitlements_path), packaging.build_settings, debug_signature_input, error), error.c_str());
        CodeDirectorySpecialSlots debug_entitlement_blobs;
        Require(BuildProvisioningEntitlementBlobs(debug_signature_input, debug_entitlement_blobs, error), error.c_str());
        File(profile, "mutated live profile after debug preparation");
        const std::vector<std::string> child_directories{OwnedDirectory(bound_child.bundle_identifier)};
        Require(BuildProvisioningCodeDirectoryCms(bound_child, credential, child_directories, native_cms, error), error.c_str());
        CheckAppleCmsAttributes(native_cms, child_directories);
        auto RejectDirectory = [&](const std::vector<std::string>& bytes, const PreparedEntitlementRequest& binding) {
            native_cms = "stale CMS";
            Require(!BuildProvisioningCodeDirectoryCms(binding, credential, bytes, native_cms, error) && native_cms.empty() && !error.empty(),
                "CodeDirectory CMS accepted inconsistent inputs or retained a stale signature");
        };
        RejectDirectory({}, with_certificate);
        RejectDirectory(std::vector<std::string>(7, primary_directory), with_certificate);
        RejectDirectory({primary_directory, primary_directory}, with_certificate);
        RejectDirectory({primary_directory, OwnedDirectory(with_certificate.bundle_identifier, 3)}, with_certificate);
        RejectDirectory({OwnedDirectory(bound_child.bundle_identifier)}, with_certificate);
        RejectDirectory({OwnedDirectory(with_certificate.bundle_identifier, 2, "OTHERTEAM1")}, with_certificate);
        RejectDirectory({primary_directory, OwnedDirectory(with_certificate.bundle_identifier, 1, "OTHERTEAM1")}, with_certificate);
        auto invalid_cms_binding = with_certificate;
        const auto profile_identity_offset = invalid_cms_binding.profile_cms.find("OWNEDTEAM.*");
        Require(profile_identity_offset != std::string::npos, "owned CMS profile identity not found");
        invalid_cms_binding.profile_cms[profile_identity_offset] = 'X';
        RejectDirectory({primary_directory}, invalid_cms_binding);
        auto malformed_directory = primary_directory;
        for (const auto [offset, value] : std::vector<std::pair<std::size_t, uint32_t>>{
            {0, 0}, {4, 52}, {8, 0x20600}, {12, 2}, {16, 0xffffffff}, {20, 0xffffffff},
            {24, 0xffffffff}, {28, 0xffffffff}, {40, 1}, {44, 88}, {48, 0}}) {
            malformed_directory = primary_directory; PutDirectoryWord(malformed_directory, offset, value);
            RejectDirectory({malformed_directory}, with_certificate);
        }
        for (const auto [offset, value] : std::vector<std::pair<std::size_t, char>>{{36, 20}, {37, 0}, {38, 1}}) {
            malformed_directory = primary_directory; malformed_directory[offset] = value;
            RejectDirectory({malformed_directory}, with_certificate);
        }
        RejectDirectory({primary_directory.substr(0, 51)}, with_certificate);
        malformed_directory = primary_directory; malformed_directory.back() = 'x';
        RejectDirectory({malformed_directory}, with_certificate);
        // Real linker-produced Mach-O images are inputs to the signing stage.
        // Compiler/AppBuilder metadata propagation and SDK behavior are not
        // under test here. No Mach-O offsets/page hashes are pre-resolved.
        const auto clang = ToolPaths::SwiftBin({}) / "clang.exe";
        const auto lld = ToolPaths::LlvmBin({}) / "ld64.lld.exe";
        Require(fs::is_regular_file(clang) && fs::is_regular_file(lld), "native signing test requires real managed Clang and Mach-O LLD");
        const auto owned_source = root / "signing-probe.c";
        File(owned_source, "volatile char data[5000] = {1}; int main(void) { return data[0]; }\n");
        for (const auto& architecture : {std::wstring(L"arm64"), std::wstring(L"x86_64")}) {
            const auto object = root / (architecture + L".o"), executable_path = root / (architecture + L"-probe");
            const auto triple = architecture == L"arm64" ? L"arm64-apple-ios17.0" : L"x86_64-apple-ios17.0-simulator";
            const auto platform = architecture == L"arm64" ? L"ios" : L"ios-simulator";
            const auto compile = Win32Process::Run(clang.wstring(), {clang.wstring(), L"-target", triple, L"-c", owned_source.wstring(), L"-o", object.wstring()}, root.wstring());
            Require(compile.launched && compile.exit_code == 0, compile.std_err.c_str());
            const auto link = Win32Process::Run(lld.wstring(), {lld.wstring(), L"-arch", architecture, L"-platform_version", platform,
                L"17.0", L"26.5", L"-e", L"_main", L"-adhoc_codesign", L"-o", executable_path.wstring(), object.wstring()}, root.wstring());
            Require(link.launched && link.exit_code == 0, link.std_err.c_str());
            const auto image = Bytes(executable_path);
            MachOSigningLayout signing_layout;
            Require(InspectMachOSigningLayout(image, signing_layout, error), error.c_str());
            auto BigWord = [](const std::string& bytes, std::size_t position) {
                Require(position <= bytes.size() && bytes.size() - position >= 4, "linker signature word outside image");
                uint32_t value = 0;
                for (int i = 0; i < 4; ++i) value = (value << 8) | static_cast<unsigned char>(bytes[position + i]);
                return value;
            };
            const auto original_signature = image.substr(signing_layout.signature_offset, signing_layout.signature_size);
            Require(BigWord(original_signature, 0) == 0xfade0cc0 && BigWord(original_signature, 8) == 1 && BigWord(original_signature, 12) == 0,
                "LLD fixture did not emit its original CodeDirectory signature");
            const auto original_cd_offset = BigWord(original_signature, 16);
            const auto original_cd_size = BigWord(original_signature, original_cd_offset + 4);
            Require(original_cd_offset <= original_signature.size() && original_cd_size <= original_signature.size() - original_cd_offset,
                "LLD CodeDirectory is outside its signature");
            const auto original_directory = original_signature.substr(original_cd_offset, original_cd_size);
            Require(VerifyMachOCodeDirectory(image, original_directory, {}, error), error.c_str());
            // Native signing-stage integration on copied owned target products.
            // The linker image is stage input, not an AppBuilder/SDK build proof.
            const auto resource_bundle = root / "resource-signing-stage" / architecture / with_certificate.bundle_path.filename();
            fs::create_directories(resource_bundle.parent_path());
            fs::copy(with_certificate.bundle_path, resource_bundle, fs::copy_options::recursive);
            const auto resource_child = resource_bundle / bound_child.bundle_path.lexically_relative(with_certificate.bundle_path);
            ParsedEntitlements actual_child_info(Bytes(resource_child / "Info.plist"));
            File(resource_child / actual_child_info.String("CFBundleExecutable"), image);
            File(resource_child / "embedded.mobileprovision", bound_child.profile_cms);
            BundleResourceSeal child_resources;
            Require(BuildFlatBundleResourceSeal(resource_child, child_resources, error), error.c_str());
            const CodeDirectorySpecialSlots child_external{{1, child_resources.info_plist}, {3, child_resources.code_resources}};
            std::string signed_child_image;
            Require(SignProvisionedThinMachO(image, bound_child, credential, child_external, child_entitlement_blobs, signed_child_image, error), error.c_str());
            File(child_resources.executable_path, signed_child_image);
            File(resource_child / "_CodeSignature" / "CodeResources", child_resources.code_resources);
            Require(VerifyFlatBundleResourceSeal(resource_child, child_resources.code_resources, error) &&
                VerifyProvisionedThinMachO(Bytes(child_resources.executable_path), bound_child, credential, child_external, child_entitlement_blobs, error), error.c_str());
            ParsedEntitlements actual_root_info(Bytes(resource_bundle / "Info.plist"));
            File(resource_bundle / actual_root_info.String("CFBundleExecutable"), image);
            File(resource_bundle / "embedded.mobileprovision", with_certificate.profile_cms);
            File(resource_bundle / "Assets" / "owned-resource.bin", "actual native resource stage bytes");
            BundleResourceSeal bundle_resources;
            Require(BuildFlatBundleResourceSeal(resource_bundle, bundle_resources, error), error.c_str());
            ParsedEntitlements resource_document(bundle_resources.code_resources);
            const auto nested_executable_key_u8 = child_resources.executable_path.lexically_relative(resource_bundle).generic_u8string();
            const std::string nested_executable_key(reinterpret_cast<const char*>(nested_executable_key_u8.data()), nested_executable_key_u8.size());
            const auto nested_entry = plist_dict_get_item(plist_dict_get_item(resource_document.value, "files2"), nested_executable_key.c_str());
            uint64_t nested_hash_size = 0; const auto nested_hash = plist_get_data_ptr(plist_dict_get_item(nested_entry, "hash2"), &nested_hash_size);
            Require(nested_hash && nested_hash_size == 32 && std::string_view(nested_hash, 32) == IndependentDirectoryDigest(signed_child_image, L"SHA256", 32),
                "parent resource producer failed to seal the complete actual signed child executable");
            CodeDirectorySpecialSlots slots = root_entitlement_blobs;
            slots.emplace(1, bundle_resources.info_plist);
            slots.emplace(3, bundle_resources.code_resources);
            std::string generated;
            Require(BuildMachOCodeDirectory(image, with_certificate.bundle_identifier, "OWNEDTEAM1", slots, generated, error), error.c_str());
            Require(VerifyMachOCodeDirectory(image, generated, slots, error), error.c_str());
            const auto page_hash_offset = BigWord(generated, 16), page_count = BigWord(generated, 28);
            Require(BigWord(generated, 32) == signing_layout.signature_offset && page_count > 1, "native CodeDirectory used an injected or incomplete signing region");
            for (uint32_t page = 0; page < page_count; ++page) {
                const auto offset = static_cast<std::size_t>(page) * 4096;
                const auto size = std::min<std::size_t>(4096, signing_layout.signature_offset - offset);
                Require(generated.substr(page_hash_offset + static_cast<std::size_t>(page) * 32, 32) ==
                    IndependentDirectoryDigest(image.substr(offset, size), L"SHA256", 32), "generated Mach-O page differs from independent hash");
            }
            for (const auto& [slot, value] : slots)
                Require(generated.substr(page_hash_offset - slot * 32, 32) == IndependentDirectoryDigest(value, L"SHA256", 32), "generated special slot differs from independent hash");
            Require(BuildProvisioningCodeDirectoryCms(with_certificate, credential, {generated}, native_cms, error) && VerifyNativeCms(native_cms, generated),
                "real Mach-O -> native CodeDirectory -> checked CMS path failed");
            CheckAppleCmsAttributes(native_cms, {generated});
            const CodeDirectorySpecialSlots external_signature_slots{{1, slots.at(1)}, {3, slots.at(3)}};
            CodeDirectorySpecialSlots embedded_signature_blobs;
            Require(BuildProvisioningEntitlementBlobs(with_certificate, embedded_signature_blobs, error), error.c_str());
            Require(ValidateProvisioningEntitlementBlobs(with_certificate, embedded_signature_blobs, error), error.c_str());
            std::string written_image;
            Require(SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, embedded_signature_blobs, written_image, error), error.c_str());
            Require(VerifyProvisionedThinMachO(written_image, with_certificate, credential, external_signature_slots, embedded_signature_blobs, error), error.c_str());
            File(bundle_resources.executable_path, written_image);
            File(resource_bundle / "_CodeSignature" / "CodeResources", bundle_resources.code_resources);
            Require(VerifyFlatBundleResourceSeal(resource_bundle, bundle_resources.code_resources, error) &&
                VerifyProvisionedThinMachO(Bytes(bundle_resources.executable_path), with_certificate, credential, external_signature_slots, embedded_signature_blobs, error), error.c_str());
            auto changed_child_image = signed_child_image; changed_child_image.back() ^= 1; File(child_resources.executable_path, changed_child_image);
            Require(!VerifyFlatBundleResourceSeal(resource_bundle, bundle_resources.code_resources, error), "parent resource seal accepted altered child signature bytes");
            File(child_resources.executable_path, signed_child_image);
            Require(VerifyFlatBundleResourceSeal(resource_bundle, bundle_resources.code_resources, error), "restored owned child no longer matches resource seal");
            Require(Bytes(executable_path) == image, "in-memory signature writer modified the original executable");
            MachOSigningLayout written_layout;
            Require(InspectMachOSigningLayout(written_image, written_layout, error) && written_layout.signature_offset == signing_layout.signature_offset &&
                written_layout.signature_size != signing_layout.signature_size, "native writer did not derive and update its reserved signature layout");
            const auto written_signature = written_image.substr(written_layout.signature_offset, written_layout.signature_size);
            Require(BigWord(written_signature, 8) == 4 && BigWord(written_signature, 12) == 0 && BigWord(written_signature, 20) == 5 &&
                BigWord(written_signature, 28) == 7 && BigWord(written_signature, 36) == 0x10000, "native writer emitted wrong SuperBlob slots");
            const auto written_cd_offset = BigWord(written_signature, 16), written_cms_offset = BigWord(written_signature, 40);
            const auto written_cd = written_signature.substr(written_cd_offset, BigWord(written_signature, written_cd_offset + 4));
            const auto written_cms = written_signature.substr(written_cms_offset + 8, BigWord(written_signature, written_cms_offset + 4) - 8);
            Require(VerifyNativeCms(written_cms, written_cd), "published Mach-O CMS failed separate signature verification");
            CheckAppleCmsAttributes(written_cms, {written_cd});
            Require(BigWord(written_cd, 80) == 0 && BigWord(written_cd, 84) == 1,
                "non-debug executable gained entitlement-derived execution flags");
            std::string debug_image;
            Require(SignProvisionedThinMachO(image, debug_signature_input, credential, external_signature_slots, debug_entitlement_blobs, debug_image, error) &&
                VerifyProvisionedThinMachO(debug_image, debug_signature_input, credential, external_signature_slots, debug_entitlement_blobs, error), error.c_str());
            MachOSigningLayout debug_layout;
            Require(InspectMachOSigningLayout(debug_image, debug_layout, error), error.c_str());
            const auto debug_superblob = debug_image.substr(debug_layout.signature_offset, debug_layout.signature_size);
            const auto debug_cd_offset = BigWord(debug_superblob, 16), debug_cms_offset = BigWord(debug_superblob, 40);
            const auto debug_cd = debug_superblob.substr(debug_cd_offset, BigWord(debug_superblob, debug_cd_offset + 4));
            Require(BigWord(debug_cd, 80) == 0 && BigWord(debug_cd, 84) == 0x11,
                "profile-derived debug entitlement failed to reach generated CodeDirectory execution flags");
            auto wrong_debug_cd = debug_cd; PutDirectoryWord(wrong_debug_cd, 84, 1);
            std::string wrong_debug_cms;
            Require(BuildProvisioningCodeDirectoryCms(debug_signature_input, credential, {wrong_debug_cd}, wrong_debug_cms, error) &&
                VerifyNativeCms(wrong_debug_cms, wrong_debug_cd), "negative-control CMS is not authentic");
            CheckAppleCmsAttributes(wrong_debug_cms, {wrong_debug_cd});
            Require(wrong_debug_cms.size() == BigWord(debug_superblob, debug_cms_offset + 4) - 8,
                "owned fixed-size RSA CMS fixture unexpectedly changed length");
            auto authenticated_wrong_flags = debug_image;
            authenticated_wrong_flags.replace(debug_layout.signature_offset + debug_cd_offset, wrong_debug_cd.size(), wrong_debug_cd);
            authenticated_wrong_flags.replace(debug_layout.signature_offset + debug_cms_offset + 8, wrong_debug_cms.size(), wrong_debug_cms);
            Require(!VerifyProvisionedThinMachO(authenticated_wrong_flags, debug_signature_input, credential, external_signature_slots, debug_entitlement_blobs, error) &&
                error.find("flags") != std::string::npos, "authentic CMS hid a mismatch between execution flags and sealed entitlements");
            const auto library_path = root / (architecture + L"-library.dylib");
            const auto library_link = Win32Process::Run(lld.wstring(), {lld.wstring(), L"-arch", architecture, L"-platform_version", platform,
                L"17.0", L"26.5", L"-dylib", L"-adhoc_codesign", L"-o", library_path.wstring(), object.wstring()}, root.wstring());
            Require(library_link.launched && library_link.exit_code == 0, library_link.std_err.c_str());
            const auto library_image = Bytes(library_path);
            MachOSigningLayout library_layout;
            Require(InspectMachOSigningLayout(library_image, library_layout, error) && !library_layout.main_executable,
                "linker-produced dylib incorrectly identified as main executable");
            std::string library_directory;
            Require(BuildMachOCodeDirectory(library_image, with_certificate.bundle_identifier, "OWNEDTEAM1", {}, library_directory, error) &&
                VerifyMachOCodeDirectory(library_image, library_directory, {}, error), error.c_str());
            Require(BigWord(library_directory, 80) == 0 && BigWord(library_directory, 84) == 0, "dylib without entitlements gains execution privileges");
            // Forced library entitlements are byte-stage input to this generic
            // contract, not a framework provisioning/bundle selection proof.
            Require(BuildMachOCodeDirectory(library_image, debug_signature_input.bundle_identifier, "OWNEDTEAM1", debug_entitlement_blobs, library_directory, error) &&
                VerifyMachOCodeDirectory(library_image, library_directory, debug_entitlement_blobs, error), error.c_str());
            Require(BigWord(library_directory, 80) == 0 && BigWord(library_directory, 84) == 0x10, "forced library rights incorrectly add main-binary bit");
            auto wrong_library_directory = library_directory; PutDirectoryWord(wrong_library_directory, 84, 0x11);
            Require(!VerifyMachOCodeDirectory(library_image, wrong_library_directory, debug_entitlement_blobs, error), "dylib accepted a false main-binary bit");
            const auto written_der_offset = BigWord(written_signature, 32);
            Require(VerifyEntitlementsDer(with_certificate.profile_signature_entitlements_xml,
                std::string_view(written_signature).substr(written_der_offset + 8, BigWord(written_signature, written_der_offset + 4) - 8), error), error.c_str());
            auto VerifyWrittenReject = [&](const std::string& candidate) {
                Require(!VerifyProvisionedThinMachO(candidate, with_certificate, credential, external_signature_slots, embedded_signature_blobs, error) && !error.empty(),
                    "altered native signed Mach-O was accepted");
            };
            auto altered_written = written_image;
            altered_written[written_layout.signature_offset - 1] ^= 1; VerifyWrittenReject(altered_written);
            altered_written = written_image;
            altered_written[written_layout.signature_offset + written_cms_offset + 8 + written_cms.size() - 1] ^= 1; VerifyWrittenReject(altered_written);
            altered_written = written_image;
            const auto embedded_offset = BigWord(written_signature, 24);
            altered_written[written_layout.signature_offset + embedded_offset + 8] ^= 1; VerifyWrittenReject(altered_written);
            altered_written = written_image; altered_written.back() = 1; VerifyWrittenReject(altered_written);
            altered_written = written_image;
            PutDirectoryWord(altered_written, written_layout.signature_offset + 20, 0); VerifyWrittenReject(altered_written);
            auto changed_external = external_signature_slots; changed_external[1] += "altered Info.plist";
            Require(!VerifyProvisionedThinMachO(written_image, with_certificate, credential, changed_external, embedded_signature_blobs, error), "altered external Info slot accepted");
            auto wrong_embedded = embedded_signature_blobs; wrong_embedded[5].back() ^= 1;
            Require(!VerifyProvisionedThinMachO(written_image, with_certificate, credential, external_signature_slots, wrong_embedded, error), "wrong expected embedded entitlement blob accepted");
            auto bad_frame = embedded_signature_blobs; bad_frame[5] = "not a wrapped entitlement blob";
            std::string stale_image = "stale signed image";
            Require(!SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, bad_frame, stale_image, error) && stale_image.empty(),
                "malformed embedded frame accepted or retained stale signed output");
            stale_image = "stale signed image";
            Require(!SignProvisionedThinMachO(image, invalid_cms_binding, credential, external_signature_slots, embedded_signature_blobs, stale_image, error) && stale_image.empty(),
                "signature writer bypassed tampered profile binding or retained stale output");
            for (const auto& altered_binding : altered_signature_inputs) {
                auto matching_blobs = embedded_signature_blobs;
                matching_blobs[5].resize(8);
                matching_blobs[5] += altered_binding.profile_signature_entitlements_xml;
                PutDirectoryWord(matching_blobs[5], 4, static_cast<uint32_t>(matching_blobs[5].size()));
                stale_image = "stale unauthorized signature";
                Require(!SignProvisionedThinMachO(image, altered_binding, credential, external_signature_slots, matching_blobs, stale_image, error) && stale_image.empty(),
                    "native writer signed an altered entitlement snapshot with a matching supplied XML blob");
                Require(!VerifyProvisionedThinMachO(written_image, altered_binding, credential, external_signature_slots, embedded_signature_blobs, error),
                    "independent reader accepted altered entitlement authority");
            }
            auto missing_xml = embedded_signature_blobs; missing_xml.erase(5);
            stale_image = "stale missing XML";
            Require(!SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, missing_xml, stale_image, error) && stale_image.empty(),
                "provisioned native writer omitted required entitlement XML");
            auto wrong_der = embedded_signature_blobs; wrong_der[7].back() ^= 1;
            Require(!SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, wrong_der, stale_image, error) && stale_image.empty(),
                "native writer sealed DER inconsistent with the checked XML");
            auto missing_der = embedded_signature_blobs; missing_der.erase(7);
            Require(!SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, missing_der, stale_image, error) && stale_image.empty(),
                "native writer omitted mandatory DER entitlements");
            auto unrelated_xml = embedded_signature_blobs;
            unrelated_xml[5].resize(8); unrelated_xml[5] += "<plist version=\"1.0\"><dict/></plist>";
            PutDirectoryWord(unrelated_xml[5], 4, static_cast<uint32_t>(unrelated_xml[5].size()));
            Require(!SignProvisionedThinMachO(image, with_certificate, credential, external_signature_slots, unrelated_xml, stale_image, error) && stale_image.empty(),
                "native writer sealed an XML blob unrelated to its checked request");
            std::string resigned;
            Require(SignProvisionedThinMachO(written_image, with_certificate, credential, external_signature_slots, embedded_signature_blobs, resigned, error) &&
                VerifyProvisionedThinMachO(resigned, with_certificate, credential, external_signature_slots, embedded_signature_blobs, error), "native repeated signing did not verify");
            auto in_place = image;
            Require(SignProvisionedThinMachO(in_place, with_certificate, credential, external_signature_slots, embedded_signature_blobs, in_place, error) &&
                VerifyProvisionedThinMachO(in_place, with_certificate, credential, external_signature_slots, embedded_signature_blobs, error), "native signature output alias invalidated its input view");
            auto overlapping_vm = image;
            const auto linkedit_name = overlapping_vm.find("__LINKEDIT", 32);
            Require(linkedit_name != std::string::npos, "real linker LINKEDIT metadata missing");
            for (int i = 0; i < 8; ++i) overlapping_vm[linkedit_name + 16 + i] = 0;
            stale_image = "stale VM output";
            Require(!SignProvisionedThinMachO(overlapping_vm, with_certificate, credential, external_signature_slots, embedded_signature_blobs, stale_image, error) &&
                stale_image.empty() && error.find("VM segments") != std::string::npos, "native layout update accepted overlapping VM segments");
            auto altered_image = image;
            altered_image[signing_layout.signature_offset - 1] ^= 1;
            Require(!VerifyMachOCodeDirectory(altered_image, generated, slots, error), "last signed Mach-O byte tampering accepted");
            altered_image = image; altered_image[signing_layout.signature_offset] ^= 1;
            Require(VerifyMachOCodeDirectory(altered_image, generated, slots, error), "page verifier accidentally hashes the excluded signature region");
            auto altered_slots = slots; altered_slots[3] += "changed";
            Require(!VerifyMachOCodeDirectory(image, generated, altered_slots, error), "altered resource slot accepted");
            altered_slots = slots; altered_slots.erase(5);
            Require(!VerifyMachOCodeDirectory(image, generated, altered_slots, error), "missing sealed special slot accepted");
            altered_slots = slots; altered_slots[2] = "unexpected requirements";
            Require(!VerifyMachOCodeDirectory(image, generated, altered_slots, error), "unexpected absent slot accepted");
            altered_slots = slots; altered_slots[8] = "unsealed slot";
            Require(!VerifyMachOCodeDirectory(image, generated, altered_slots, error), "special input beyond the signed slot count accepted");
            auto altered_directory = generated; PutDirectoryWord(altered_directory, 32, signing_layout.signature_offset - 1);
            Require(!VerifyMachOCodeDirectory(image, altered_directory, slots, error), "shortened CodeDirectory coverage accepted");
            altered_directory = generated; PutDirectoryWord(altered_directory, 84, 0x11);
            Require(!VerifyMachOCodeDirectory(image, altered_directory, slots, error), "unexpected unsigned-page privilege accepted");
            auto malformed_entitlement_slots = slots; malformed_entitlement_slots[5] = "not a framed XML entitlement blob";
            std::string malformed_entitlement_directory = "stale";
            Require(!BuildMachOCodeDirectory(image, with_certificate.bundle_identifier, "OWNEDTEAM1", malformed_entitlement_slots,
                malformed_entitlement_directory, error) && malformed_entitlement_directory.empty(), "flag producer accepted malformed sealed XML input");
            altered_directory = generated; altered_directory[39] = 32;
            Require(!VerifyMachOCodeDirectory(image, altered_directory, slots, error), "invalid CodeDirectory page shift accepted");
            altered_directory = generated; altered_directory[72 + 7] ^= 1;
            Require(!VerifyMachOCodeDirectory(image, altered_directory, slots, error), "wrong executable segment metadata accepted");
            std::string stale_directory = "stale directory";
            Require(!BuildMachOCodeDirectory(image.substr(0, 31), with_certificate.bundle_identifier, "OWNEDTEAM1", slots, stale_directory, error) && stale_directory.empty(),
                "malformed Mach-O retained stale generated CodeDirectory");
            auto malformed_image = image;
            malformed_image[20] = '\xff'; malformed_image[21] = '\xff'; malformed_image[22] = '\xff'; malformed_image[23] = '\xff';
            MachOSigningLayout stale_layout = signing_layout;
            Require(!InspectMachOSigningLayout(malformed_image, stale_layout, error) && stale_layout.signature_offset == 0,
                "malformed load commands retained stale Mach-O layout");
            malformed_image = image; malformed_image[36] = 1;
            Require(!InspectMachOSigningLayout(malformed_image, stale_layout, error), "invalid load-command size accepted");
            for (const bool deadline : {false, true}) {
                auto stopped_context = std::make_shared<OperationContext>();
                if (deadline) stopped_context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() - std::chrono::seconds(1));
                else stopped_context->RequestCancellation();
                OperationBinding stopped_binding(stopped_context);
                stale_directory = "stale cancelled directory";
                Require(!BuildMachOCodeDirectory(image, with_certificate.bundle_identifier, "OWNEDTEAM1", slots, stale_directory, error) &&
                    stale_directory.empty() && error.find("cancelled or deadline") != std::string::npos,
                    "cancelled/deadline native hash production continued or retained stale output");
                Require(!VerifyMachOCodeDirectory(image, generated, slots, error) && error.find("cancelled or deadline") != std::string::npos,
                    "cancelled/deadline native page verification continued");
            }
        }
        File(owned_p12, signer.P12(owned_password));
        auto corrupt_snapshot = with_certificate;
        const auto signed_content = corrupt_snapshot.profile_cms.find("OWNEDTEAM.*");
        Require(signed_content != std::string::npos, "owned certificate CMS content not found");
        corrupt_snapshot.profile_cms[signed_content] = 'X';
        Require(!ValidateProvisioningSigningCertificate(corrupt_snapshot, credential, error),
            "certificate binding accepted tampered CMS bytes");
        auto wrong_binding = with_certificate;
        wrong_binding.bundle_identifier = "not_an_identifier";
        Require(!ValidateProvisioningSigningCertificate(wrong_binding, credential, error),
            "certificate check accepted a malformed bound bundle identity");

        TestSigner other_signer; other_signer.Initialize();
        auto CertificateCheck = [&](const std::string& xml, bool expected) {
            auto prepared = with_certificate;
            prepared.profile_cms = signer.Sign(xml);
            Require(ValidateProvisioningSigningCertificate(prepared, credential, error) == expected && expected == error.empty(),
                "native profile/certificate authorization decision or diagnostic incorrect");
        };
        CertificateCheck(ProfileCertificates("OWNEDTEAM.*", all_rights, {other_signer.Der()}), false);
        CertificateCheck(Profile("OWNEDTEAM.*", "OWNEDTEAM", all_rights), false);
        CertificateCheck(ProfileCertificates("OWNEDTEAM.*", all_rights, {}), false);
        CertificateCheck(ProfileCertificates("OWNEDTEAM.*", all_rights, {signer.Der(), "not X.509"}), false);
        CertificateCheck(ProfileCertificates("OWNEDTEAM.*", all_rights, {other_signer.Der(), signer.Der()}), true);
        CertificateCheck(ProfileCertificates("OWNEDTEAM.org.unrelated", all_rights, {signer.Der()}), false);

        // The actual packager gets its target/settings/products from the owned
        // discovery pipeline. Real supplied credential files are stage inputs;
        // no signing-certificate selection or profile authorization is injected.
        auto with_credentials = with_extension;
        with_credentials.p12_path = owned_p12.wstring();
        with_credentials.dpapi_password_path = protected_password.wstring();
        File(profile, signer.Sign(ProfileCertificates("OWNEDTEAM.*", all_rights, {other_signer.Der()})));
        const auto bad_certificate = RejectExtension(with_credentials, "does not authorize the prepared signing certificate", "credential-not-authorized");
        Require(bad_certificate.prepared_entitlement_requests.empty(), "rejected certificate retained a misleading signing input set");
        failure = false;
        for (const auto& event : sink->received)
            failure |= event.kind == "task.completed" && event.data.GetString("name") == "signing.certificate-preflight"
                && event.data.GetString("state") == "failed";
        Require(failure && diagnostics.str().find(Win32Process::ToNarrow(owned_password)) == std::string::npos,
            "certificate rejection lost its structured event or disclosed the password");
        Require(ProtectedCredentialStore::Write(protected_password, L"wrong owned password", CredentialPurpose::SigningPassword),
            "owned wrong-password fixture failed");
        RejectExtension(with_credentials, "Unable to import signing P12 in memory", "credential-wrong-password");
        Require(!PrepareSigningCredential(owned_p12, L"wrong owned password", credential, error) &&
            credential.CertificateDer().empty(), "wrong password accepted or retained stale private-key identity");
        File(owned_p12, signer.P12(owned_password, false));
        Require(!PrepareSigningCredential(owned_p12, owned_password, credential, error) && credential.CertificateDer().empty(),
            "certificate-only PFX accepted as a signing credential");
        File(owned_p12, signer.P12(owned_password, true, other_signer.cert));
        Require(!PrepareSigningCredential(owned_p12, owned_password, credential, error) &&
            error.find("multiple private-key identities") != std::string::npos && credential.CertificateDer().empty(),
            "ambiguous PFX identities were selected silently");
        TestSigner expired_signer; expired_signer.Initialize(-730);
        File(owned_p12, expired_signer.P12(owned_password));
        Require(!PrepareSigningCredential(owned_p12, owned_password, credential, error) &&
            error.find("expired or not yet valid") != std::string::npos, "expired signing certificate accepted");
        TestSigner future_signer; future_signer.Initialize(365);
        File(owned_p12, future_signer.P12(owned_password));
        Require(!PrepareSigningCredential(owned_p12, owned_password, credential, error) &&
            error.find("expired or not yet valid") != std::string::npos, "future signing certificate accepted");
        File(owned_p12, "not a PFX");
        Require(!PrepareSigningCredential(owned_p12, owned_password, credential, error) && credential.CertificateDer().empty(),
            "malformed PFX accepted");
        Require(!PrepareSigningCredential(root / "missing.p12", owned_password, credential, error), "missing PFX accepted");

        // Isolated value-contract cases; these do not claim metadata propagation.
        const auto request = root / "contract.entitlements";
        auto EntitlementCheck = [&](const std::string& requested, const std::string& granted, bool expected) {
            File(request, "<plist version=\"1.0\"><dict>" + requested + "</dict></plist>");
            File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", granted)));
            Require(ValidateProvisioningRequestedEntitlements(profile, app, request, {}, error) == expected,
                "entitlement allow-list decision wrong");
            Require(expected == error.empty(), "entitlement diagnostic missing/stale");
        };
        EntitlementCheck("<key>keychain-access-groups</key><array><string>$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)</string></array>",
            "<key>keychain-access-groups</key><array><string>OWNEDTEAM.*</string></array>", true);
        EntitlementCheck("<key>application-identifier</key><string>OWNEDTEAM.org.other</string>", "", false);
        EntitlementCheck("<key>get-task-allow</key><true/>", "<key>get-task-allow</key><false/>", false);
        EntitlementCheck("<key>get-task-allow</key><false/>", "<key>get-task-allow</key><false/>", true);
        EntitlementCheck("<key>keychain-access-groups</key><array><string>OTHERTEAM.org.owned</string></array>",
            "<key>keychain-access-groups</key><array><string>OWNEDTEAM.*</string></array>", false);
        EntitlementCheck("<key>keychain-access-groups</key><string>OWNEDTEAM.org.owned</string>",
            "<key>keychain-access-groups</key><array><string>OWNEDTEAM.*</string></array>", false);
        EntitlementCheck("<key>com.apple.security.application-groups</key><array><string>$(UNKNOWN_GROUP)</string></array>", rights, false);
        Require(error.find("$(UNKNOWN_GROUP) is not defined") != std::string::npos, "unresolved entitlement variable not named");
        // Xcode resolves the product identity by its Info.plist key as well.
        EntitlementCheck("<key>keychain-access-groups</key><array><string>$(AppIdentifierPrefix)$(CFBundleIdentifier)</string></array>",
            "<key>keychain-access-groups</key><array><string>OWNEDTEAM.*</string></array>", true);
        // Selected keychain groups and profile-controlled booleans are preserved;
        // absent/contradictory grants cannot be replaced by guessed defaults.
        const auto signature_rights = "<key>keychain-access-groups</key><array><string>OWNEDTEAM.shared</string><string>OWNEDTEAM.extra</string></array>"
            "<key>get-task-allow</key><true/><key>beta-reports-active</key><true/>";
        File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", signature_rights)));
        File(request, "<plist version=\"1.0\"><dict><key>keychain-access-groups</key><array><string>$(AppIdentifierPrefix)shared</string></array></dict></plist>");
        PreparedEntitlementRequest selected;
        Require(PrepareProvisioningSignatureInput(profile, app, request, {}, selected, error), "authorized custom keychain groups rejected");
        ParsedEntitlements selected_xml(selected.profile_signature_entitlements_xml);
        Require(plist_array_get_size(plist_dict_get_item(selected_xml.value, "keychain-access-groups")) == 1 &&
            selected.profile_signature_entitlements_xml.find("OWNEDTEAM.extra") == std::string::npos &&
            selected.profile_signature_entitlements_xml.find("OWNEDTEAM.shared") != std::string::npos,
            "signature preparation widened selected keychain access");
        for (const auto key : {"get-task-allow", "beta-reports-active"}) {
            uint8_t value = 0; plist_get_bool_val(plist_dict_get_item(selected_xml.value, key), &value);
            Require(value == 1, "profile boolean was guessed from build configuration or dropped");
        }
        auto RejectSignature = [&](const std::string& grants) {
            File(profile, signer.Sign(Profile("OWNEDTEAM.*", "OWNEDTEAM", grants)));
            selected = root_request;
            Require(!PrepareProvisioningSignatureInput(profile, app, {}, {}, selected, error) &&
                !error.empty() && selected.profile_signature_entitlements_xml.empty() && selected.requested_entitlements_xml.empty(),
                "inconsistent profile grants produced signature inputs or retained stale outputs");
        };
        RejectSignature("<key>com.apple.developer.team-identifier</key><string>OTHERTEAM1</string>");
        RejectSignature("<key>get-task-allow</key><string>false</string>");
        RejectSignature("<key>beta-reports-active</key><string>true</string>");
        RejectSignature("<key>keychain-access-groups</key><array><string>OTHERTEAM.*</string></array>");
        File(profile, signer.Sign(Profile("OWNEDTEAM.*")));
        File(request, "<plist version=\"1.0\"><dict><key>keychain-access-groups</key><array><string>OWNEDTEAM.*</string></array></dict></plist>");
        Require(!PrepareProvisioningSignatureInput(profile, app, request, {}, selected, error),
            "signature inputs retained a keychain grant wildcard as a concrete group");
        File(profile, signer.Sign(Profile("OWNEDTEAM.*")));
        Require(!PrepareProvisioningSignatureInput(profile, app, root / "missing.entitlements", {}, selected, error),
            "signature preparation treated a missing configured file as no declaration");
        File(request, "not a plist");
        Require(!ValidateProvisioningRequestedEntitlements(profile, app, request, {}, error), "malformed entitlements accepted");
        Require(!ValidateProvisioningRequestedEntitlements(profile, app, root / "missing.entitlements", {}, error), "missing configured entitlements silently discarded");
        Require(Bytes(fs::path(packaging.code_sign_entitlements_path)) == original_entitlements,
            "signing preflight modified upstream entitlement contents");
        std::cout << "PASS: actual bundle inputs and ephemeral credentials reject unauthorized identities/rights/certificates before signing\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL: " << ex.what() << "\n"; return 1; }
}
