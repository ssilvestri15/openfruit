#include "signing_credential.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <vector>
#include <set>
namespace OpenFruit {
namespace {
struct SensitiveBytes {
    std::vector<BYTE> value;
    ~SensitiveBytes() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};
struct TemporaryStore {
    HCERTSTORE value = nullptr;
    ~TemporaryStore() { if (value) CertCloseStore(value, 0); }
};
struct Certificate {
    PCCERT_CONTEXT value = nullptr;
    ~Certificate() { if (value) CertFreeCertificateContext(value); }
};
bool CompleteDerValue(std::string_view value) {
    // Signed attributes contain one complete DER value, never BER indefinite
    // lengths or trailing bytes. Nested semantics belong to the attribute owner.
    if (value.size() < 2) return false;
    const auto tag = static_cast<unsigned char>(value[0]);
    if (!tag || (tag & 31) == 31) return false;
    std::size_t offset = 2, length = static_cast<unsigned char>(value[1]);
    if (length & 128) {
        const auto count = length & 127;
        if (!count || count > sizeof(std::size_t) || count > value.size() - offset || value[offset] == '\0') return false;
        length = 0;
        for (std::size_t i = 0; i < count; ++i)
            length = (length << 8) | static_cast<unsigned char>(value[offset++]);
        if (length < 128) return false;
    }
    return length == value.size() - offset;
}
bool KeyPossession(PCCERT_CONTEXT cert) {
    // A CMS challenge is verified with the encoded certificate's public key,
    // rather than assuming that an imported key-context property matches it.
    constexpr BYTE challenge[] = "OPENFRUIT signing credential preflight v1";
    const BYTE* data = challenge;
    DWORD size = sizeof(challenge) - 1, encoded_size = 0;
    CRYPT_SIGN_MESSAGE_PARA sign{};
    sign.cbSize = sizeof(sign); sign.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign.pSigningCert = cert; sign.HashAlgorithm.pszObjId = const_cast<char*>(szOID_NIST_sha256);
    sign.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    sign.cMsgCert = 1; sign.rgpMsgCert = &cert;
    if (!CryptSignMessage(&sign, TRUE, 1, &data, &size, nullptr, &encoded_size) || !encoded_size || encoded_size > 1024 * 1024)
        return false;
    std::vector<BYTE> encoded(encoded_size);
    if (!CryptSignMessage(&sign, TRUE, 1, &data, &size, encoded.data(), &encoded_size)) return false;
    CRYPT_VERIFY_MESSAGE_PARA verify{};
    verify.cbSize = sizeof(verify); verify.dwMsgAndCertEncodingType = sign.dwMsgEncodingType;
    return CryptVerifyDetachedMessageSignature(&verify, 0, encoded.data(), encoded_size, 1, &data, &size, nullptr) != FALSE;
}
}
struct SigningCredential::Impl {
    TemporaryStore store;
    Certificate cert;
    std::string der;
};
SigningCredential::SigningCredential() = default;
SigningCredential::~SigningCredential() = default;
SigningCredential::SigningCredential(SigningCredential&&) noexcept = default;
SigningCredential& SigningCredential::operator=(SigningCredential&&) noexcept = default;
const std::string& SigningCredential::CertificateDer() const noexcept {
    static const std::string empty;
    return impl_ ? impl_->der : empty;
}
bool SigningCredential::SignDetachedCms(std::string_view content,
    const std::vector<CmsAuthenticatedAttribute>& attributes, std::string& cms, std::string& error) const {
    bool signed_message = false;
    OperationSpan phase("signing.native-cms", JsonValue::ObjectValue(), [&] { return signed_message; });
    cms.clear(); error.clear();
    if (!impl_ || content.empty() || content.size() > 16 * 1024 * 1024 || attributes.size() > 32) {
        error = "Native CMS requires a prepared credential and bounded nonempty content/attributes."; return false;
    }
    if (CertVerifyTimeValidity(nullptr, impl_->cert.value->pCertInfo) != 0) {
        error = "Signing certificate is expired or not yet valid."; return false;
    }
    std::vector<std::vector<CRYPT_ATTR_BLOB>> values(attributes.size());
    std::vector<CRYPT_ATTRIBUTE> encoded(attributes.size());
    std::set<std::string> oids;
    std::size_t total = 0;
    for (std::size_t i = 0; i < attributes.size(); ++i) {
        const auto& attr = attributes[i];
        if (attr.oid.empty() || attr.oid.size() > 128 || attr.oid.find('\0') != std::string::npos ||
            !oids.insert(attr.oid).second || attr.values_der.empty() || attr.values_der.size() > 6 ||
            attr.oid == szOID_RSA_contentType || attr.oid == szOID_RSA_messageDigest) {
            error = "Native CMS attribute set is invalid or duplicates automatic attributes."; return false;
        }
        for (const auto& value : attr.values_der) {
            if (value.size() > 1024 * 1024 - total || !CompleteDerValue(value)) {
                error = "Native CMS authenticated attributes require bounded complete DER values."; return false;
            }
            total += value.size();
            values[i].push_back({static_cast<DWORD>(value.size()), reinterpret_cast<BYTE*>(const_cast<char*>(value.data()))});
        }
        encoded[i] = {const_cast<char*>(attr.oid.c_str()), static_cast<DWORD>(values[i].size()), values[i].data()};
    }
    // Include certificates supplied by the P12, without chain downloads or
    // silently importing additional certificates into any persistent store.
    struct Certificates {
        std::vector<PCCERT_CONTEXT> values;
        ~Certificates() { for (const auto cert : values) CertFreeCertificateContext(cert); }
    } certificates;
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(impl_->store.value, current))) {
        if (certificates.values.size() == 64) {
            CertFreeCertificateContext(current);
            error = "Native CMS certificate input exceeds the supported chain limit."; return false;
        }
        const auto retained = CertDuplicateCertificateContext(current);
        if (!retained) {
            CertFreeCertificateContext(current);
            error = "Unable to retain native CMS certificate inputs."; return false;
        }
        certificates.values.push_back(retained);
    }
    if (GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND)) {
        error = "Unable to enumerate native CMS certificate inputs."; return false;
    }
    CRYPT_SIGN_MESSAGE_PARA sign{};
    sign.cbSize = sizeof(sign); sign.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign.pSigningCert = impl_->cert.value; sign.HashAlgorithm.pszObjId = const_cast<char*>(szOID_NIST_sha256);
    sign.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    sign.cMsgCert = static_cast<DWORD>(certificates.values.size()); sign.rgpMsgCert = certificates.values.data();
    sign.cAuthAttr = static_cast<DWORD>(encoded.size()); sign.rgAuthAttr = encoded.data();
    const BYTE* bytes = reinterpret_cast<const BYTE*>(content.data());
    DWORD size = static_cast<DWORD>(content.size()), cms_size = 0;
    if (!CryptSignMessage(&sign, TRUE, 1, &bytes, &size, nullptr, &cms_size) || !cms_size || cms_size > 16 * 1024 * 1024) {
        error = "Unable to size native detached CMS."; return false;
    }
    std::string result(cms_size, '\0');
    if (!CryptSignMessage(&sign, TRUE, 1, &bytes, &size, reinterpret_cast<BYTE*>(result.data()), &cms_size)) {
        error = "Unable to sign native detached CMS."; return false;
    }
    result.resize(cms_size);
    cms = std::move(result); signed_message = true;
    return true;
}
bool PrepareSigningCredential(const std::filesystem::path& p12, const std::wstring& password,
    SigningCredential& credential, std::string& error) {
    bool prepared = false;
    OperationSpan phase("signing.credential-preflight", JsonValue::ObjectValue(), [&] { return prepared; });
    credential = {}; error.clear();
    if (password.find(L'\0') != std::wstring::npos) {
        error = "Signing password contains an unsupported embedded NUL."; return false;
    }
    std::ifstream file(p12, std::ios::binary | std::ios::ate);
    const auto size = file ? file.tellg() : std::streampos(-1);
    if (size <= 0 || size > 16 * 1024 * 1024) {
        error = "Signing P12 is missing, empty or exceeds the credential input limit."; return false;
    }
    SensitiveBytes bytes;
    bytes.value.resize(static_cast<std::size_t>(size));
    file.seekg(0); file.read(reinterpret_cast<char*>(bytes.value.data()), bytes.value.size());
    if (!file) { error = "Unable to read signing P12."; return false; }
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(bytes.value.size()), bytes.value.data()};
    auto result = std::make_unique<SigningCredential::Impl>();
    result->store.value = PFXImportCertStore(&blob, password.c_str(), PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP | CRYPT_USER_KEYSET);
    if (!result->store.value) {
        error = "Unable to import signing P12 in memory; check its format and protected password."; return false;
    }
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(result->store.value, current))) {
        DWORD context_size = 0;
        if (!CertGetCertificateContextProperty(current, CERT_KEY_CONTEXT_PROP_ID, nullptr, &context_size)) continue;
        if (result->cert.value) {
            CertFreeCertificateContext(current);
            error = "Signing P12 contains multiple private-key identities; select an unambiguous credential."; return false;
        }
        result->cert.value = CertDuplicateCertificateContext(current);
        if (!result->cert.value) {
            CertFreeCertificateContext(current);
            error = "Unable to retain the ephemeral signing certificate."; return false;
        }
    }
    if (GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND)) {
        error = "Unable to enumerate signing P12 identities."; return false;
    }
    if (!result->cert.value) {
        error = "Signing P12 contains no certificate with an ephemeral private key."; return false;
    }
    if (CertVerifyTimeValidity(nullptr, result->cert.value->pCertInfo) != 0) {
        error = "Signing certificate is expired or not yet valid."; return false;
    }
    if (!KeyPossession(result->cert.value)) {
        error = "Signing P12 private key cannot produce a signature verified by its certificate."; return false;
    }
    result->der.assign(reinterpret_cast<const char*>(result->cert.value->pbCertEncoded), result->cert.value->cbCertEncoded);
    credential.impl_ = std::move(result);
    prepared = true;
    return true;
}
}
