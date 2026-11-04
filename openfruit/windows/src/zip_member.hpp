#pragma once
#include "zip_inventory.hpp"
#include <string_view>
namespace OpenFruit {
struct ZipMemberResult {
    bool stream_verified = false;
    std::string body, sha256, sha384, error;
    std::uint64_t compressed_bytes = 0, decoded_bytes = 0;
    JsonValue ToJson() const;
};
using ZipMemberSink = std::function<bool(std::string_view)>;
// Sink receives unverified decoded bytes; callers must quarantine/rollback until
// the final stream/CRC/digests pass. Memory consumption does not grow with file size.
ZipMemberResult StreamZipMember(const ZipInventoryResult&, const std::string& name,
    const ZipInventoryRead&, const ZipMemberSink&, CancellationToken = {},
    std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
// Bounded metadata-member read; does not publish files or authenticate provenance.
ZipMemberResult ReadZipMember(const ZipInventoryResult&, const std::string& name,
    const ZipInventoryRead&, CancellationToken = {},
    std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
ZipMemberResult ReadRemoteZipMember(const RangeTransferRequest&, const std::string& name);
ZipMemberResult ReadRemoteZipMember(const ZipInventoryResult&, const std::string& name,
    const RangeTransferRequest& options = {});
}
