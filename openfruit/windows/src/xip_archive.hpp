#pragma once
#include "cancellation.hpp"
#include "json_value.hpp"
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <vector>
namespace OpenFruit {
enum class XipStatus { Completed, Stopped, InvalidArchive, IoFailure, ResourceLimit, Cancelled, TimedOut, ConsumerFailure };
const char* XipStatusName(XipStatus) noexcept;
struct XipEntry {
    std::string path;
    std::uint64_t size = 0;
    std::uint32_t device = 0, inode = 0, mode = 0, links = 0;
};
enum class XipVisit { Continue, Stop };
// Visitors receive original CPIO metadata and streaming bytes, including link
// payloads. No paths are materialized by this reader. Extraction must preserve
// link/clone semantics and validate destination paths separately.
class XipVisitor {
public:
    virtual ~XipVisitor() = default;
    virtual void Begin(const XipEntry&) = 0;
    virtual void Data(std::span<const std::uint8_t>) = 0;
    virtual XipVisit End() = 0;
};
struct XipReadOptions {
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::uint64_t max_decoded_bytes = 256ull * 1024 * 1024 * 1024;
    std::uint64_t max_entries = 4000000;
    // Optional, at most every 100 ms: (payload bytes read, payload bytes total).
    std::function<void(std::uint64_t completed, std::uint64_t total)> progress;
};
struct XipReadResult {
    XipStatus status = XipStatus::InvalidArchive;
    std::uint64_t entries = 0, encoded_bytes = 0, encoded_total = 0, decoded_bytes = 0;
    bool toc_checksum_verified = false, content_checksum_verified = false, xar_signature_valid = false;
    // Neither certificate result binds the archive to a trusted catalog.
    bool apple_signing_chain_valid = false, apple_revocation_valid = false;
    std::string error;
};
class XipArchive {
public:
    // Structural read, NOT publisher/signature verification or installation.
    static XipReadResult Walk(const std::filesystem::path&, XipVisitor&, const XipReadOptions& = {});
};
struct SDKArchiveMetadata {
    XipReadResult read;
    std::string sdk_root, version, canonical_name;
    bool Found() const noexcept { return read.status == XipStatus::Stopped && !version.empty(); }
    JsonValue ToJson() const;
    static SDKArchiveMetadata DiscoverIos(const std::filesystem::path&, const XipReadOptions& = {});
};
struct XipMemberMetadata {
    XipEntry entry;
    bool selected_by_filter = false;
    std::string content_kind;
    std::uint32_t cpu_type_hint = 0;
};
struct XipInventoryOptions {
    XipReadOptions read;
    std::size_t max_metadata_entries = 512000;
    std::size_t max_path_bytes = 128ull * 1024 * 1024;
};
struct XipInventory {
    XipReadResult read;
    std::vector<XipMemberMetadata> members;
    bool Complete() const noexcept { return read.status == XipStatus::Completed; }
    JsonValue ToJson() const;
    // Full read, raw CPIO metadata only; includes regular-file hardlink/clone
    // partners by device/inode. No member content, extraction or publication.
    // Literal case-sensitive path substring; empty selects all members.
    static XipInventory Inspect(const std::filesystem::path&, const std::string& path_filter,
        const XipInventoryOptions& = {});
};
}
