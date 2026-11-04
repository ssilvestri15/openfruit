#pragma once
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
namespace OpenFruit {
struct CmsAuthenticatedAttribute {
    std::string oid;
    std::vector<std::string> values_der;
};
// Holds a single verified certificate/private-key identity in a temporary native
// store. Keys are never persisted; no certificate is added to user/system stores.
// This establishes key possession and certificate dates, not Apple trust.
class SigningCredential {
public:
    SigningCredential();
    ~SigningCredential();
    SigningCredential(SigningCredential&&) noexcept;
    SigningCredential& operator=(SigningCredential&&) noexcept;
    SigningCredential(const SigningCredential&) = delete;
    SigningCredential& operator=(const SigningCredential&) = delete;
    const std::string& CertificateDer() const noexcept;
    // Uses only the retained native identity. No password, P12 reread, network
    // lookup or external process; values are complete DER attribute values.
    bool SignDetachedCms(std::string_view content,
        const std::vector<CmsAuthenticatedAttribute>& attributes,
        std::string& cms, std::string& error) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend bool PrepareSigningCredential(const std::filesystem::path&, const std::wstring&,
        SigningCredential&, std::string&);
};
bool PrepareSigningCredential(const std::filesystem::path& p12, const std::wstring& password,
    SigningCredential& credential, std::string& error);
}
