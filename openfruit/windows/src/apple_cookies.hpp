#pragma once
#include "config.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace OpenFruit {
struct AppleCookie {
    std::string domain, path, name, value;
    bool subdomains = false, secure = false, http_only = false;
    std::uint64_t expires = 0;
};
class AppleCookieJar {
public:
    // Netscape cookie-file format. Non-Apple domains are not imported.
    static bool Parse(const std::string&, AppleCookieJar&);
    // Import one Set-Cookie field from an HTTPS response by an Apple host.
    // This updates only this in-memory jar; it never persists response tokens.
    bool ImportHttpsResponseCookie(const std::string& origin_host, const std::string& origin_path,
        const std::string& header, std::uint64_t now);
    // Accept a browser cookie only after validating its Apple scope and syntax.
    bool AddBrowserCookie(AppleCookie cookie);
    std::string Serialize() const;
    // Only HTTPS requests to Apple hosts; never forward a prebuilt header on redirects.
    std::string ForHttpsRequest(const std::string& host, const std::string& path, std::uint64_t now) const;
    std::size_t Count() const noexcept { return cookies_.size(); }
private:
    std::vector<AppleCookie> cookies_;
};
enum class AppleCookieImportStatus { Succeeded, InvalidFile, InvalidCookies, ProtectionFailed, PublicationFailed };
struct AppleCookieImportResult {
    AppleCookieImportStatus status = AppleCookieImportStatus::InvalidFile;
    std::size_t count = 0;
    bool Succeeded() const noexcept { return status == AppleCookieImportStatus::Succeeded; }
};
class AppleCookieStore {
public:
    static AppleCookieImportResult Import(Secrets&, const std::filesystem::path& source,
        const std::filesystem::path& metadata);
    static AppleCookieImportResult Protect(Secrets&, const AppleCookieJar&,
        const std::filesystem::path& metadata);
    static bool Load(const Secrets&, AppleCookieJar&);
    // Atomically disables future loads. Does not revoke Apple's server session
    // or erase ciphertext already referenced by another running operation.
    static bool Clear(Secrets&, const std::filesystem::path& metadata);
};
}
