#include "xip_archive.hpp"
#include "operation_events.hpp"
#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <windows.h>

namespace OpenFruit {
namespace {
using Identity = std::pair<std::uint32_t, std::uint32_t>;
bool RegularLinked(const XipEntry& entry) { return (entry.mode & 0170000) == 0100000 && entry.links > 1; }
struct InventoryFailure { XipStatus status; const char* code; };
class InventoryVisitor final : public XipVisitor {
public:
    InventoryVisitor(const std::string& filter, const XipInventoryOptions& options) : filter(filter), options(options) {}
    void Begin(const XipEntry& entry) override {
        if (records.size() >= options.max_metadata_entries || path_bytes > options.max_path_bytes ||
            entry.path.size() > options.max_path_bytes - path_bytes)
            Fail(XipStatus::ResourceLimit, "archive.inventory.metadata_limit");
        if (!entry.path.empty() && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            entry.path.data(), static_cast<int>(entry.path.size()), nullptr, 0))
            Fail(XipStatus::InvalidArchive, "archive.inventory.invalid_path_utf8");
        path_bytes += entry.path.size();
        records.push_back({entry, entry.path.find(filter) != std::string::npos, {}});
        prefix.clear();
    }
    void Data(std::span<const std::uint8_t> data) override {
        if (prefix.size() < 32)
            prefix.append(reinterpret_cast<const char*>(data.data()), std::min<std::size_t>(32 - prefix.size(), data.size()));
    }
    XipVisit End() override {
        auto& record = records.back();
        const auto type = record.entry.mode & 0170000;
        if (type == 0040000) record.content_kind = "directory";
        else if (type == 0120000) record.content_kind = "symlink";
        else if (type != 0100000) record.content_kind = "other";
        else if (prefix.starts_with("NULLcanary") && RegularLinked(record.entry)) record.content_kind = "xip-clone-marker";
        else if (prefix.empty()) record.content_kind = "empty-or-hardlink";
        else {
            const auto byte = [&](unsigned i) { return static_cast<unsigned char>(prefix[i]); };
            const auto magic = prefix.size() < 4 ? 0u :
                (std::uint32_t(byte(0)) << 24) | (std::uint32_t(byte(1)) << 16) | (std::uint32_t(byte(2)) << 8) | byte(3);
            if (magic == 0xcafebabe || magic == 0xcafebabf || magic == 0xbebafeca || magic == 0xbfbafeca)
                record.content_kind = "mach-o-fat";
            else if (magic == 0xcffaedfe || magic == 0xfeedfacf) record.content_kind = "mach-o-64";
            else if (magic == 0xcefaedfe || magic == 0xfeedface) record.content_kind = "mach-o-32";
            else if (prefix.starts_with("MZ")) record.content_kind = "pe-signature";
            else if (magic == 0x7f454c46) record.content_kind = "elf-signature";
            else record.content_kind = "regular";
            if (prefix.size() >= 12 && (record.content_kind == "mach-o-64" || record.content_kind == "mach-o-32")) {
                const bool big = magic == 0xfeedfacf || magic == 0xfeedface;
                for (unsigned i = 0; i < 4; ++i)
                    record.cpu_type_hint |= std::uint32_t(byte(4 + i)) << (8 * (big ? 3 - i : i));
            }
        }
        return XipVisit::Continue;
    }
    [[noreturn]] void Fail(XipStatus status, const char* code) { failure = InventoryFailure{status, code}; throw *failure; }
    std::vector<XipMemberMetadata> records;
    std::optional<InventoryFailure> failure;
private:
    const std::string& filter;
    const XipInventoryOptions& options;
    std::size_t path_bytes = 0;
    std::string prefix;
};
}
XipInventory XipInventory::Inspect(const std::filesystem::path& archive, const std::string& filter,
    const XipInventoryOptions& options) {
    XipInventory result;
    if (filter.size() > 32768 || filter.find('\0') != std::string::npos) {
        result.read.error = "archive.inventory.invalid_filter"; return result;
    }
    InventoryVisitor visitor(filter, options);
    result.read = XipArchive::Walk(archive, visitor, options.read);
    if (visitor.failure) { result.read.status = visitor.failure->status; result.read.error = visitor.failure->code; }
    if (!result.Complete()) return result;
    std::set<Identity> partners;
    for (const auto& record : visitor.records) if (record.selected_by_filter && RegularLinked(record.entry))
        partners.emplace(record.entry.device, record.entry.inode);
    for (auto& record : visitor.records) if (record.selected_by_filter ||
        (RegularLinked(record.entry) && partners.contains({record.entry.device, record.entry.inode})))
        result.members.push_back(std::move(record));
    return result;
}
JsonValue XipInventory::ToJson() const {
    auto output = JsonValue::ObjectValue(), items = JsonValue::ArrayValue();
    output.Set("schema_version", JsonValue::Number("1"));
    output.Set("status", JsonValue::String(XipStatusName(read.status)));
    output.Set("inventory_complete", JsonValue::Boolean(Complete()));
    output.Set("published", JsonValue::Boolean(false));
    output.Set("publisher_verified", JsonValue::Boolean(false));
    output.Set("scope", JsonValue::String("Raw archive metadata and linked partners; content signatures are hints, not image validation"));
    output.Set("diagnostic_code", JsonValue::String(read.error));
    output.Set("entries_read", JsonValue::Number(std::to_string(read.entries)));
    output.Set("encoded_bytes", JsonValue::Number(std::to_string(read.encoded_bytes)));
    output.Set("encoded_total", JsonValue::Number(std::to_string(read.encoded_total)));
    output.Set("decoded_bytes", JsonValue::Number(std::to_string(read.decoded_bytes)));
    output.Set("toc_checksum_verified", JsonValue::Boolean(read.toc_checksum_verified));
    output.Set("content_checksum_verified", JsonValue::Boolean(read.content_checksum_verified));
    output.Set("xar_signature_valid", JsonValue::Boolean(read.xar_signature_valid));
    output.Set("apple_signing_chain_valid", JsonValue::Boolean(read.apple_signing_chain_valid));
    output.Set("apple_revocation_valid", JsonValue::Boolean(read.apple_revocation_valid));
    for (const auto& member : members) {
        auto item = JsonValue::ObjectValue();
        item.Set("path", JsonValue::String(member.entry.path));
        item.Set("size", JsonValue::Number(std::to_string(member.entry.size)));
        item.Set("mode", JsonValue::Number(std::to_string(member.entry.mode)));
        item.Set("device", JsonValue::Number(std::to_string(member.entry.device)));
        item.Set("inode", JsonValue::Number(std::to_string(member.entry.inode)));
        item.Set("links", JsonValue::Number(std::to_string(member.entry.links)));
        item.Set("selected_by_filter", JsonValue::Boolean(member.selected_by_filter));
        item.Set("content_kind_hint", JsonValue::String(member.content_kind));
        item.Set("cpu_type_hint", JsonValue::Number(std::to_string(member.cpu_type_hint)));
        items.ArrayItems().push_back(std::move(item));
    }
    output.Set("members", std::move(items)); return output;
}
}
