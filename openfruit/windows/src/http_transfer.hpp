#pragma once
#include "cancellation.hpp"
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
namespace OpenFruit {
enum class TransferStatus { Succeeded, InvalidRequest, Busy, IoFailure, NetworkFailure, HttpFailure,
    IntegrityFailure, Cancelled, TimedOut };
struct TransferRequest {
    std::wstring url;
    std::filesystem::path destination;
    std::string expected_sha256;
    std::uint64_t max_bytes = 32ULL * 1024 * 1024 * 1024;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    // Called anew for each HTTPS destination. The caller owns credential scope.
    std::function<std::wstring(const std::wstring& host, const std::wstring& path)> cookie_header;
    // Restricted exception for owned local protocol tests; credentials are never sent over HTTP.
    bool allow_loopback_http = false;
    // Optional progress callback: (downloaded_bytes, total_bytes)
    std::function<void(std::uint64_t downloaded_bytes, std::uint64_t total_bytes)> progress_callback;
    // Opt-in immutable final-file reuse after full SHA-256 verification. The caller
    // retains any ArtifactLease needed across download and later consumption.
    bool reuse_verified_destination = false;
};
struct TransferResult {
    TransferStatus status = TransferStatus::InvalidRequest;
    std::uint64_t bytes = 0;
    unsigned long native_error = 0;
    unsigned long http_status = 0;
    bool resumed = false;
    bool reused = false;
    bool Succeeded() const noexcept { return status == TransferStatus::Succeeded; }
};
struct JsonPostRequest {
    std::wstring url;
    std::string body = "{}";
    std::uint64_t max_bytes = 8ULL * 1024 * 1024;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::function<std::wstring(const std::wstring& host, const std::wstring& path)> cookie_header;
    // Restricted exception for owned local protocol tests; no credentials over HTTP.
    bool allow_loopback_http = false;
};
struct JsonPostResult {
    JsonPostResult() = default;
    JsonPostResult(const JsonPostResult&) = delete;
    JsonPostResult& operator=(const JsonPostResult&) = delete;
    JsonPostResult(JsonPostResult&&) noexcept = default;
    JsonPostResult& operator=(JsonPostResult&&) = delete;
    ~JsonPostResult();
    TransferStatus status = TransferStatus::InvalidRequest;
    std::string body;
    std::vector<std::wstring> set_cookie_headers;
    // Only GetBytes reports a bounded redirect destination to the caller;
    // it never follows it. Origin policy remains with the owning service.
    std::wstring redirect_url;
    unsigned long native_error = 0, http_status = 0;
    bool Succeeded() const noexcept { return status == TransferStatus::Succeeded; }
};
struct StagedTransferRequest {
    std::wstring url;
    std::filesystem::path staging_directory;
    std::uint64_t expected_bytes = 0;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::function<std::wstring(const std::wstring& host, const std::wstring& path)> cookie_header;
    bool allow_loopback_http = false;
    // Optional: (downloaded_bytes, total_bytes).
    std::function<void(std::uint64_t downloaded_bytes, std::uint64_t total_bytes)> progress_callback;
};
struct StagedTransferResult {
    TransferResult transfer;
    std::filesystem::path path;
    bool Succeeded() const noexcept { return transfer.Succeeded(); }
};
struct RangeTransferRequest {
    std::wstring url;
    std::uint64_t offset = 0, bytes = 0;
    // Zero allows discovery on the first read. Bind every subsequent read to
    // the returned total and strong ETag from that same original URL.
    std::uint64_t expected_total = 0;
    std::wstring expected_etag;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    bool allow_loopback_http = false;
};
struct RangeTransferResult {
    TransferStatus status = TransferStatus::InvalidRequest;
    std::string body;
    std::wstring etag;
    std::uint64_t total = 0;
    unsigned long native_error = 0, http_status = 0;
    bool Succeeded() const noexcept { return status == TransferStatus::Succeeded; }
};
// Streaming WinHTTP transfer; no final destination is published before SHA-256 verification.
class HttpTransfer {
public:
    static TransferResult Download(const TransferRequest&);
    // Downloads catalog-sized bytes into quarantine only. Content authenticity
    // remains unverified; the caller must verify the complete archive before
    // publication or registration.
    static StagedTransferResult Stage(const StagedTransferRequest&);
    // Bounded in-memory JSON response. Redirects are rejected, and neither
    // request body nor response content is written to operation events.
    static JsonPostResult PostJson(const JsonPostRequest&);
    // Bounded HTTPS text response for public provider metadata. Redirects are rejected.
    static JsonPostResult GetText(const JsonPostRequest&);
    // Bounded HTTPS JSON GET response for public REST APIs (e.g. GitHub Releases).
    static JsonPostResult GetJson(const JsonPostRequest&);
    // Bounded public bytes over HTTPS. Identity encoding, no redirects, cookies,
    // implicit authentication or publication. Body storage clears on destruction.
    static JsonPostResult GetBytes(const JsonPostRequest&);
    // Exact bounded identity-encoded bytes; no redirects, cookies or implicit
    // authentication. No content publication or publisher verification.
    static RangeTransferResult ReadRange(const RangeTransferRequest&);
private:
    static TransferResult RunTransfer(const TransferRequest&, std::uint64_t expected_bytes, bool staging);
};
}
