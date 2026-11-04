#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace OpenFruit {

/// Writes Apple-compatible binary Header Map (.hmap) files consumed natively by Clang.
class HeaderMapWriter {
public:
    HeaderMapWriter() = default;

    /// Adds a mapping from an include name (e.g. "osd.h" or "MyModule/MyHeader.h")
    /// to an on-disk header file path.
    void AddMapping(std::string_view include_name, const std::filesystem::path& target_path);

    /// Writes the header map to the specified file path.
    /// Returns true on success.
    bool Write(const std::filesystem::path& output_path) const;

    std::size_t Size() const noexcept {
        return mappings_.size();
    }

    bool Empty() const noexcept {
        return mappings_.empty();
    }

    /// Apple's standard hash function for header maps.
    static inline uint32_t HashKey(std::string_view str) noexcept {
        uint32_t result = 0;
        for (unsigned char c : str) {
            result += static_cast<uint32_t>(static_cast<char>(std::tolower(c))) * 13;
        }
        return result;
    }

private:
    std::unordered_map<std::string, std::filesystem::path> mappings_;
};

} // namespace OpenFruit
