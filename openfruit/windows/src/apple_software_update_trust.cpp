#include "apple_software_update_trust.hpp"
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <algorithm>
#include <array>
#include <memory>
#include <string_view>
namespace OpenFruit {
namespace {
// SHA-256 identities of the Apple Root CA and Apple Software Update
// Certification Authority published at apple.com/certificateauthority/.
constexpr std::string_view root_hash = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024";
constexpr std::string_view update_ca_hash = "1299e9bfe776a29ff452f8c4f5e55f3b4dfd2934349dd1850b8274f35c71745c";
constexpr char apple_code_signing[] = "1.2.840.113635.100.4.1";
constexpr char production_update[] = "1.2.840.113635.100.6.1.29.2";
constexpr char update_ca_marker[] = "1.2.840.113635.100.6.2.19";
struct CertificateDeleter {
    void operator()(const CERT_CONTEXT* certificate) const { if (certificate) CertFreeCertificateContext(certificate); }
};
using Certificate = std::unique_ptr<const CERT_CONTEXT, CertificateDeleter>;
struct Store {
    Store() = default;
    HCERTSTORE handle = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    ~Store() { if (handle) CertCloseStore(handle, 0); }
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
};
struct Engine {
    HCERTCHAINENGINE handle = nullptr;
    ~Engine() { if (handle) CertFreeCertificateChainEngine(handle); }
};
struct Chain {
    PCCERT_CHAIN_CONTEXT handle = nullptr;
    ~Chain() { if (handle) CertFreeCertificateChain(handle); }
};
bool HasHash(PCCERT_CONTEXT certificate, std::string_view expected) {
    std::array<BYTE, 32> digest{};
    DWORD size = static_cast<DWORD>(digest.size());
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, certificate->pbCertEncoded,
        certificate->cbCertEncoded, digest.data(), &size) || size != digest.size()) return false;
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < digest.size(); ++i)
        if (expected[2 * i] != hex[digest[i] >> 4] || expected[2 * i + 1] != hex[digest[i] & 15]) return false;
    return true;
}
bool HasExtension(PCCERT_CONTEXT certificate, const char* oid) {
    return CertFindExtension(oid, certificate->pCertInfo->cExtension,
        certificate->pCertInfo->rgExtension) != nullptr;
}
bool HasSigningUsage(PCCERT_CONTEXT certificate) {
    const auto* extension = CertFindExtension(szOID_ENHANCED_KEY_USAGE,
        certificate->pCertInfo->cExtension, certificate->pCertInfo->rgExtension);
    if (!extension) return false;
    PCERT_ENHKEY_USAGE usage = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
        extension->Value.pbData, extension->Value.cbData, CRYPT_DECODE_ALLOC_FLAG,
        nullptr, &usage, &size)) return false;
    bool found = false;
    for (DWORD index = 0; index < usage->cUsageIdentifier; ++index)
        found |= std::string_view(usage->rgpszUsageIdentifier[index]) == apple_code_signing;
    LocalFree(usage);
    BYTE key_usage[2]{};
    return found && CertGetIntendedKeyUsage(X509_ASN_ENCODING, certificate->pCertInfo,
        key_usage, sizeof(key_usage)) && (key_usage[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE);
}
}
AppleSoftwareUpdateTrust VerifyAppleSoftwareUpdateChain(const std::vector<std::vector<std::uint8_t>>& encoded) {
    AppleSoftwareUpdateTrust result;
    if (encoded.size() < 3 || encoded.size() > 8) return result;
    std::vector<Certificate> certificates;
    certificates.reserve(encoded.size());
    for (const auto& bytes : encoded) {
        if (bytes.empty() || bytes.size() > 65536) return result;
        certificates.emplace_back(CertCreateCertificateContext(X509_ASN_ENCODING,
            bytes.data(), static_cast<DWORD>(bytes.size())));
        if (!certificates.back()) return result;
    }
    const auto* leaf = certificates.front().get();
    if (!HasSigningUsage(leaf) || !HasExtension(leaf, production_update)) return result;
    const CERT_CONTEXT* root = nullptr;
    const CERT_CONTEXT* update_ca = nullptr;
    for (std::size_t index = 1; index < certificates.size(); ++index) {
        const auto* certificate = certificates[index].get();
        if (HasHash(certificate, root_hash)) root = certificate;
        if (HasHash(certificate, update_ca_hash) && HasExtension(certificate, update_ca_marker))
            update_ca = certificate;
    }
    if (!root || !update_ca) return result;
    Store trusted_root, intermediates;
    if (!trusted_root.handle || !intermediates.handle ||
        !CertAddCertificateContextToStore(trusted_root.handle, root, CERT_STORE_ADD_ALWAYS, nullptr) ||
        !CertAddCertificateContextToStore(intermediates.handle, update_ca, CERT_STORE_ADD_ALWAYS, nullptr)) return result;
    CERT_CHAIN_ENGINE_CONFIG config{};
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = trusted_root.handle;
    Engine engine;
    if (!CertCreateCertificateChainEngine(&config, &engine.handle)) return result;
    CERT_CHAIN_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    // Only the certificates carried by the archive may complete this chain.
    Chain chain;
    if (!CertGetCertificateChain(engine.handle, leaf, nullptr, intermediates.handle,
        &parameters, CERT_CHAIN_DISABLE_AIA | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE |
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, nullptr, &chain.handle) || !chain.handle ||
        chain.handle->TrustStatus.dwErrorStatus || chain.handle->cChain != 1) return result;
    const auto* simple = chain.handle->rgpChain[0];
    if (simple->cElement != 3 || !CertCompareCertificate(X509_ASN_ENCODING,
            simple->rgpElement[0]->pCertContext->pCertInfo, leaf->pCertInfo) ||
        !HasHash(simple->rgpElement[1]->pCertContext, update_ca_hash) ||
        !HasHash(simple->rgpElement[2]->pCertContext, root_hash)) return result;
    CERT_CHAIN_POLICY_PARA policy{}; policy.cbSize = sizeof(policy);
    CERT_CHAIN_POLICY_STATUS status{}; status.cbSize = sizeof(status);
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chain.handle, &policy, &status) || status.dwError)
        return result;
    result.chain_valid = true;
    // Revocation is required for both the signing leaf and issuing Software
    // Update CA. URL retrieval is permitted; unknown results fail closed.
    parameters.dwUrlRetrievalTimeout = 10000;
    Chain revoked;
    const DWORD flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT | CERT_CHAIN_DISABLE_AIA |
        CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
    if (!CertGetCertificateChain(engine.handle, leaf, nullptr, intermediates.handle,
        &parameters, flags, nullptr, &revoked.handle) || !revoked.handle ||
        revoked.handle->TrustStatus.dwErrorStatus) return result;
    status = {}; status.cbSize = sizeof(status);
    result.revocation_valid = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE,
        revoked.handle, &policy, &status) && !status.dwError;
    return result;
}
}
