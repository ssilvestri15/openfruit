#pragma once
#include "http_transfer.hpp"
#include "json_value.hpp"
#include <functional>
#include <optional>
#include <vector>
namespace OpenFruit {
struct ZipInventoryMember {
    std::string name;
    std::uint64_t compressed = 0, uncompressed = 0, local_offset = 0;
    std::uint32_t crc32 = 0, attributes = 0;
    std::uint16_t method = 0, flags = 0;
};
struct ZipInventoryResult {
    bool directory_validated = false, zip64 = false;
    std::uint64_t archive_bytes = 0, directory_offset = 0, directory_bytes = 0;
    std::string directory_sha256, error;
    // Retain the same source identity for future selective member reads.
    // URL/validator are not serialized or included in diagnostic events.
    std::wstring source_url, source_etag;
    std::vector<ZipInventoryMember> members;
    JsonValue ToJson() const;
};
// Reader must return exactly requested immutable original bytes or failure.
// Inventory validates directory metadata only, not local headers/member data.
using ZipInventoryRead = std::function<std::optional<std::string>(std::uint64_t, std::uint64_t)>;
ZipInventoryResult InspectZipInventory(std::uint64_t archive_bytes, const ZipInventoryRead&,
    CancellationToken = {}, std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
ZipInventoryResult InspectRemoteZip(const RangeTransferRequest&);
}
