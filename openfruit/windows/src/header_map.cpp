#include "header_map.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace fs = std::filesystem;

namespace OpenFruit {

#pragma pack(push, 1)
struct HMapHeader {
    uint32_t magic = 0x686d6170; // 'hmap'
    uint16_t version = 1;
    uint16_t reserved = 0;
    uint32_t strings_offset = 0;
    uint32_t num_entries = 0;
    uint32_t num_buckets = 0;
    uint32_t max_val_len = 0;
};

struct HMapBucket {
    uint32_t key = 0;
    uint32_t prefix = 0;
    uint32_t suffix = 0;
};
#pragma pack(pop)

void HeaderMapWriter::AddMapping(
    std::string_view include_name,
    const std::filesystem::path& target_path
) {
    if (include_name.empty() || target_path.empty()) {
        return;
    }
    mappings_[std::string(include_name)] = target_path;
}

bool HeaderMapWriter::Write(const std::filesystem::path& output_path) const {
    std::error_code ec;
    fs::create_directories(output_path.parent_path(), ec);

    // Compute power-of-two number of buckets with load factor <= 0.5
    uint32_t num_buckets = 8;
    while (num_buckets <= mappings_.size() * 2) {
        num_buckets *= 2;
    }

    // String table starts with a null byte at offset 0 (empty string).
    std::string str_table;
    str_table.push_back('\0');

    std::unordered_map<std::string, uint32_t> str_offsets;
    str_offsets[""] = 0;

    auto add_string = [&](const std::string& str) -> uint32_t {
        auto it = str_offsets.find(str);
        if (it != str_offsets.end()) {
            return it->second;
        }
        uint32_t offset = static_cast<uint32_t>(str_table.size());
        str_offsets[str] = offset;
        str_table.append(str);
        str_table.push_back('\0');
        return offset;
    };

    std::vector<HMapBucket> buckets(num_buckets, {0, 0, 0});
    uint32_t max_val_len = 0;

    for (const auto& [key, target_path] : mappings_) {
        // Use generic (forward-slash) representation for Clang compatibility.
        std::string dir = target_path.parent_path().generic_string();
        if (!dir.empty() && dir.back() != '/') {
            dir.push_back('/');
        }
        std::string filename = target_path.filename().generic_string();

        uint32_t total_len = static_cast<uint32_t>(dir.size() + filename.size());
        if (total_len > max_val_len) {
            max_val_len = total_len;
        }

        uint32_t key_off = add_string(key);
        uint32_t prefix_off = add_string(dir);
        uint32_t suffix_off = add_string(filename);

        uint32_t hash = HashKey(key);
        uint32_t idx = hash & (num_buckets - 1);
        while (buckets[idx].key != 0) {
            idx = (idx + 1) & (num_buckets - 1);
        }

        buckets[idx].key = key_off;
        buckets[idx].prefix = prefix_off;
        buckets[idx].suffix = suffix_off;
    }

    HMapHeader header;
    header.magic = 0x686d6170;
    header.version = 1;
    header.reserved = 0;
    header.strings_offset = static_cast<uint32_t>(sizeof(HMapHeader) + num_buckets * sizeof(HMapBucket));
    header.num_entries = static_cast<uint32_t>(mappings_.size());
    header.num_buckets = num_buckets;
    header.max_val_len = max_val_len;

    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    out.write(reinterpret_cast<const char*>(buckets.data()), buckets.size() * sizeof(HMapBucket));
    out.write(str_table.data(), str_table.size());

    return out.good();
}

} // namespace OpenFruit
