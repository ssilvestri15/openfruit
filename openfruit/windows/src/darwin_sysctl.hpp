#pragma once
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace OpenFruit {
struct DarwinSysctlResult {std::vector<std::uint8_t> bytes;int error=0;};
// Registry of actual native-owned guest properties. It does not invent a
// Darwin kernel version, host security configuration or optional MAC nodes.
class DarwinSysctl {
public:
    explicit DarwinSysctl(std::uint64_t guest_page_size);
    DarwinSysctlResult NameToOid(std::string_view name) const;
    DarwinSysctlResult Read(std::span<const std::int32_t> mib) const;
private:
    std::uint32_t page_size_;
};
}
