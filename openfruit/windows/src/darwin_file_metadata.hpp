#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include "json_value.hpp"
namespace OpenFruit {
struct DarwinFileTime {std::int64_t seconds=0;std::uint32_t nanoseconds=0;};
struct DarwinFileMetadata {
    std::uint32_t device=0,uid=0,gid=0,io_blocksize=0,flags=0;
    std::uint16_t mode=0,links=0;
    std::uint64_t inode=0;
    std::int64_t size=0,blocks=0;
    std::array<DarwinFileTime,4> times{};
    std::array<unsigned char,144> EncodeStat64() const;
    JsonValue ToJson() const;
};
DarwinFileTime DarwinTimeFromWindowsTicks(std::int64_t ticks) noexcept;
// Stable native SID realm. No native SID maps to guest root/nobody; collisions fail.
int DarwinPrincipalFromSid(std::span<const unsigned char> sid,std::uint32_t& id);
// Query the exact borrowed regular-file handle. No paths reopened or Apple metadata invented.
int QueryDarwinReadonlyFileMetadata(void* native_handle,DarwinFileMetadata& result);
}
