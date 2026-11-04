#pragma once
#include "apple_cookies.hpp"
#include "cancellation.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
namespace OpenFruit {
enum class AppleCatalogStatus {
    Succeeded, CredentialsUnavailable, Unauthorized, TransportFailure,
    InvalidResponse, Cancelled, TimedOut
};
struct AppleDownloadFile {
    std::string download_id, product_name, filename, remote_path, url;
    std::uint64_t bytes = 0;
};
struct AppleCatalogResult {
    AppleCatalogStatus status = AppleCatalogStatus::InvalidResponse;
    std::vector<AppleDownloadFile> xip_files;
    unsigned long http_status = 0;
    std::string diagnostic_code;
    // Only Fetch can set this after a successful request to Apple's fixed HTTPS
    // origin. A saved response parsed locally is never trusted provenance.
    bool origin_verified = false;
    // Scoped session for the download that follows this live catalog response.
    AppleCookieJar download_cookies;
    bool Succeeded() const noexcept { return status == AppleCatalogStatus::Succeeded; }
    const AppleDownloadFile* SmallestXipForProduct(const std::string& product) const noexcept;
};
class AppleDownloadCatalog {
public:
    // Parses metadata only. The caller must not treat a local body as an
    // authenticated or current Apple response.
    static AppleCatalogResult ParseUntrusted(const std::string& body);
    static AppleCatalogResult Fetch(const AppleCookieJar& cookies,
        CancellationToken cancellation = {},
        std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max());
};
}
