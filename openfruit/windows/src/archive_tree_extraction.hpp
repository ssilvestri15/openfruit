#pragma once
#include "xip_archive.hpp"
#include <functional>
namespace OpenFruit {
enum class ArchiveExtractionStatus {
    Succeeded, InvalidDestination, DestinationExists, ArchiveFailure, MissingSelection,
    UnsafePath, UnresolvedLink, UnsupportedEntry, SymbolicLinksUnavailable,
    IoFailure, ResourceLimit, Cancelled, TimedOut
};
const char* ArchiveExtractionStatusName(ArchiveExtractionStatus) noexcept;
struct ArchiveExtractionOptions {
    XipReadOptions read;
    std::size_t max_plan_entries = 512000;
    std::uint64_t max_plan_string_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_written_bytes = 32ull * 1024 * 1024 * 1024;
};
struct ArchiveExtractionResult {
    ArchiveExtractionStatus status = ArchiveExtractionStatus::ArchiveFailure;
    std::vector<std::string> member_paths;
    std::string diagnostic_code;
    std::uint64_t files = 0, selected_entries = 0, hardlinks = 0, symlinks = 0, written_bytes = 0;
    std::uint32_t native_error = 0;
    bool staging_present = false, toc_checksum_verified = false, content_checksum_verified = false, xar_signature_valid = false;
    bool apple_signing_chain_valid = false, apple_revocation_valid = false;
    bool Succeeded() const noexcept { return status == ArchiveExtractionStatus::Succeeded; }
    JsonValue ToJson() const;
};
struct ArchiveTreeSelection {
    ArchiveExtractionStatus status = ArchiveExtractionStatus::Succeeded;
    std::vector<std::string> member_paths;
    std::string diagnostic_code;
};
using ArchiveTreeSelector = std::function<ArchiveTreeSelection(const std::filesystem::path&, const XipReadOptions&)>;
class ArchiveTreeExtraction {
public:
    // Selector runs while the original archive is leased against writes/replacement.
    // Produces a fresh staging tree preserving hierarchy and link targets. Does
    // not register, publish or establish catalog provenance for runtime inputs.
    static ArchiveExtractionResult Extract(const std::filesystem::path& archive,
        const std::filesystem::path& destination, const ArchiveTreeSelector&, const ArchiveExtractionOptions& = {});
    static ArchiveExtractionResult ExtractMembers(const std::filesystem::path& archive,
        const std::filesystem::path& destination, const std::vector<std::string>& member_paths,
        const ArchiveExtractionOptions& = {});
};
}
