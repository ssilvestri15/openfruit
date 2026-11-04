#pragma once
#include "xip_archive.hpp"
namespace OpenFruit {
enum class SDKExtractionStatus {
    Succeeded, InvalidDestination, DestinationExists, ArchiveFailure, MissingSdk,
    UnsafePath, UnresolvedLink, UnsupportedEntry, SymbolicLinksUnavailable,
    IoFailure, ResourceLimit, Cancelled, TimedOut
};
const char* SDKExtractionStatusName(SDKExtractionStatus) noexcept;
struct SDKExtractionOptions {
    XipReadOptions read;
    std::size_t max_plan_entries = 512000;
    std::uint64_t max_plan_string_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_written_bytes = 32ull * 1024 * 1024 * 1024;
};
struct SDKExtractionResult {
    SDKExtractionStatus status = SDKExtractionStatus::ArchiveFailure;
    std::filesystem::path sdk_path;
    std::string version, diagnostic_code;
    std::uint64_t files = 0, selected_entries = 0, hardlinks = 0, symlinks = 0, written_bytes = 0;
    std::uint32_t native_error = 0;
    bool staging_present = false, toc_checksum_verified = false, content_checksum_verified = false, xar_signature_valid = false;
    bool apple_signing_chain_valid = false, apple_revocation_valid = false;
    bool Succeeded() const noexcept { return status == SDKExtractionStatus::Succeeded; }
    JsonValue ToJson() const;
};
class SDKArchiveExtraction {
public:
    // Destination must be absolute, absent and have an existing ordinary parent.
    // Produces an unverified staging tree with original archive hierarchy/link
    // targets; it does NOT register/publish an SDK or verify Apple provenance.
    static SDKExtractionResult ExtractIos(const std::filesystem::path& archive,
        const std::filesystem::path& destination, const SDKExtractionOptions& = {});
};
}
