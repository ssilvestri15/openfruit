#include "zip_inventory.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <algorithm>
#include <stdexcept>
#include <unordered_set>
namespace OpenFruit {
namespace {
std::uint64_t U(const std::string& b, std::size_t p, unsigned n) {
    if (p > b.size() || n > b.size() - p) throw std::runtime_error("Truncated ZIP metadata.");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= std::uint64_t(static_cast<unsigned char>(b[p+i])) << (8*i);
    return v;
}
bool SafeName(const std::string& name, bool utf8) {
    if (name.empty() || name.size() > 4096 || name.front() == '/' || name.find_first_of("\\:\0", 0, 3) != std::string::npos) return false;
    for (unsigned char c : name) if (c < 32 || c == 127 || (!utf8 && c >= 128)) return false;
    if (utf8 && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()), nullptr, 0)) return false;
    std::size_t pos = 0;
    while (pos < name.size()) {
        const auto slash = name.find('/', pos);
        const auto part = name.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        if (part.empty() || part == "." || part == "..") return false;
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return true;
}
}
ZipInventoryResult InspectZipInventory(std::uint64_t size, const ZipInventoryRead& reader,
    CancellationToken cancellation, std::chrono::steady_clock::time_point deadline) {
    ZipInventoryResult result;
    try {
        auto check = [&] {
            if (cancellation.Requested()) throw std::runtime_error("ZIP inventory cancelled.");
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("ZIP inventory deadline exceeded.");
        };
        auto read = [&](std::uint64_t offset, std::uint64_t count) {
            check();
            if (offset > size || count > size - offset || count > 64ULL*1024*1024) throw std::runtime_error("ZIP read exceeds archive bounds.");
            if (!count) return std::string{};
            auto b = reader(offset,count);
            if (!b || b->size() != count) throw std::runtime_error("Original ZIP byte acquisition failed.");
            check(); return std::move(*b);
        };
        check();
        if (!reader || size < 22 || size > 128ULL*1024*1024*1024) throw std::runtime_error("Unsupported ZIP archive size.");
        const auto tail_offset = size - std::min<std::uint64_t>(size,65557);
        const auto tail = read(tail_offset,size-tail_offset);
        std::optional<std::size_t> end;
        for (std::size_t p = tail.size()-22;; --p) {
            if (U(tail,p,4) == 0x06054b50 && U(tail,p+20,2) == tail.size()-p-22) {
                if (end) throw std::runtime_error("Ambiguous ZIP end records.");
                end = p;
            }
            if (!p) break;
        }
        if (!end) throw std::runtime_error("Original ZIP end record missing.");
        const auto p = *end, end_offset = tail_offset + p;
        if (U(tail,p+4,2) || U(tail,p+6,2)) throw std::runtime_error("Multi-disk ZIP is unsupported.");
        auto entries = U(tail,p+10,2), bytes = U(tail,p+12,4), offset = U(tail,p+16,4);
        const auto disk_entries = U(tail,p+8,2);
        std::uint64_t boundary = end_offset;
        const bool locator_present = end_offset >= 20 && p >= 20 && U(tail,p-20,4) == 0x07064b50;
        if (entries == 0xffff || disk_entries == 0xffff || bytes == 0xffffffff || offset == 0xffffffff || locator_present) {
            if (end_offset < 20) throw std::runtime_error("ZIP64 locator missing.");
            const auto locator = read(end_offset-20,20);
            if (U(locator,0,4) != 0x07064b50 || U(locator,4,4) || U(locator,16,4) != 1) throw std::runtime_error("Invalid ZIP64 locator.");
            const auto zoff = U(locator,8,8);
            if (zoff > end_offset-20 || end_offset-20-zoff < 56) throw std::runtime_error("Invalid ZIP64 end offset.");
            const auto z = read(zoff,56);
            const auto zbytes = U(z,4,8);
            if (U(z,0,4) != 0x06064b50 || zbytes < 44 || zbytes > 65536 || zbytes != end_offset-20-zoff-12 ||
                U(z,16,4) || U(z,20,4) || U(z,24,8) != U(z,32,8)) throw std::runtime_error("Invalid ZIP64 end record.");
            const auto ze = U(z,32,8), zb = U(z,40,8), zo = U(z,48,8);
            if ((entries != 0xffff && entries != ze) || (disk_entries != 0xffff && disk_entries != ze) ||
                (bytes != 0xffffffff && bytes != zb) || (offset != 0xffffffff && offset != zo)) throw std::runtime_error("ZIP32 and ZIP64 metadata disagree.");
            entries = ze; bytes = zb; offset = zo; boundary = zoff; result.zip64 = true;
        } else if (disk_entries != entries) throw std::runtime_error("ZIP entry counts disagree.");
        if (entries > 100000 || bytes > 64ULL*1024*1024 || offset > boundary || bytes != boundary-offset || entries > bytes/46)
            throw std::runtime_error("ZIP directory bounds or budget invalid.");
        const auto directory = read(offset,bytes);
        auto hash = Sha256(directory);
        if (!hash) throw std::runtime_error("ZIP directory hashing failed.");
        std::size_t cursor = 0;
        std::unordered_set<std::string> names;
        for (std::uint64_t index = 0; index < entries; ++index) {
            check();
            if (U(directory,cursor,4) != 0x02014b50) throw std::runtime_error("Invalid ZIP central member header.");
            ZipInventoryMember member;
            member.flags = static_cast<std::uint16_t>(U(directory,cursor+8,2));
            member.method = static_cast<std::uint16_t>(U(directory,cursor+10,2));
            member.crc32 = static_cast<std::uint32_t>(U(directory,cursor+16,4));
            member.compressed = U(directory,cursor+20,4); member.uncompressed = U(directory,cursor+24,4);
            const auto n = U(directory,cursor+28,2), x = U(directory,cursor+30,2), c = U(directory,cursor+32,2);
            auto disk = U(directory,cursor+34,2);
            member.attributes = static_cast<std::uint32_t>(U(directory,cursor+38,4));
            member.local_offset = U(directory,cursor+42,4);
            if (cursor > directory.size() || 46+n+x+c > directory.size()-cursor) throw std::runtime_error("ZIP member variable data truncated.");
            member.name = directory.substr(cursor+46,static_cast<std::size_t>(n));
            if (!SafeName(member.name,(member.flags&0x800)!=0) || !names.insert(member.name).second) throw std::runtime_error("Unsafe or duplicate ZIP member path.");
            if (member.flags & ~std::uint16_t(0x80e)) throw std::runtime_error("Unsupported ZIP member flags.");
            if (member.method != 0 && member.method != 8) throw std::runtime_error("Unsupported ZIP compression method.");
            const bool nu = member.uncompressed == 0xffffffff, nc = member.compressed == 0xffffffff,
                no = member.local_offset == 0xffffffff, nd = disk == 0xffff;
            std::size_t ep = cursor+46+static_cast<std::size_t>(n), extra_end = ep+static_cast<std::size_t>(x);
            bool zip_extra = false;
            while (ep < extra_end) {
                if (extra_end-ep < 4) throw std::runtime_error("Truncated ZIP extra header.");
                const auto id = U(directory,ep,2), length = U(directory,ep+2,2); ep += 4;
                if (length > extra_end-ep) throw std::runtime_error("Truncated ZIP extra payload.");
                if (id == 1) {
                    if (zip_extra) throw std::runtime_error("Duplicate ZIP64 member data.");
                    zip_extra = true;
                    auto zp = ep;
                    auto next = [&](unsigned count) {
                        if (count > ep+length-zp) throw std::runtime_error("Missing ZIP64 member field.");
                        auto value = U(directory,zp,count); zp += count; return value;
                    };
                    if (nu) member.uncompressed = next(8);
                    if (nc) member.compressed = next(8);
                    if (no) member.local_offset = next(8);
                    if (nd) disk = next(4);
                }
                ep += static_cast<std::size_t>(length);
            }
            if (((nu||nc||no||nd) && !zip_extra) || disk || member.local_offset > offset || offset-member.local_offset < 30 ||
                member.compressed > offset-member.local_offset-30 || (member.method == 0 && member.compressed != member.uncompressed))
                throw std::runtime_error("ZIP member location or size invalid.");
            result.members.push_back(std::move(member)); cursor += static_cast<std::size_t>(46+n+x+c);
        }
        if (cursor != directory.size()) throw std::runtime_error("ZIP directory has unaccounted bytes.");
        result.archive_bytes = size; result.directory_offset = offset; result.directory_bytes = bytes;
        result.directory_sha256 = *hash; result.directory_validated = true;
    } catch (const std::exception& e) { result = {}; result.error = e.what(); }
    catch (...) { result = {}; result.error = "ZIP inventory failed."; }
    return result;
}
ZipInventoryResult InspectRemoteZip(const RangeTransferRequest& options) {
    auto request = options; request.offset = 0; request.bytes = 1;
    const auto first = HttpTransfer::ReadRange(request);
    if (!first.Succeeded()) { ZipInventoryResult r; r.error = "Original ZIP identity acquisition failed."; return r; }
    request.expected_total = first.total; request.expected_etag = first.etag;
    auto inventory = InspectZipInventory(first.total,[&](std::uint64_t offset,std::uint64_t bytes) -> std::optional<std::string> {
        request.offset = offset; request.bytes = bytes;
        auto result = HttpTransfer::ReadRange(request);
        if (!result.Succeeded()) return std::nullopt;
        return std::move(result.body);
    },options.cancellation,options.deadline);
    if (inventory.directory_validated) { inventory.source_url = options.url; inventory.source_etag = first.etag; }
    return inventory;
}
JsonValue ZipInventoryResult::ToJson() const {
    auto out = JsonValue::ObjectValue();
    out.Set("directory_validated",JsonValue::Boolean(directory_validated));
    out.Set("zip64",JsonValue::Boolean(zip64));
    out.Set("publisher_verified",JsonValue::Boolean(false)); out.Set("members_verified",JsonValue::Boolean(false));
    out.Set("provider_registered",JsonValue::Boolean(false)); out.Set("error",JsonValue::String(error));
    out.Set("archive_bytes",JsonValue::Number(std::to_string(archive_bytes)));
    out.Set("directory_offset",JsonValue::Number(std::to_string(directory_offset)));
    out.Set("directory_bytes",JsonValue::Number(std::to_string(directory_bytes)));
    out.Set("directory_sha256",JsonValue::String(directory_sha256));
    auto list = JsonValue::ArrayValue();
    for (const auto& m : members) {
        auto item = JsonValue::ObjectValue(); item.Set("name",JsonValue::String(m.name));
        item.Set("compressed",JsonValue::Number(std::to_string(m.compressed))); item.Set("uncompressed",JsonValue::Number(std::to_string(m.uncompressed)));
        item.Set("local_offset",JsonValue::Number(std::to_string(m.local_offset))); item.Set("crc32",JsonValue::Number(std::to_string(m.crc32)));
        item.Set("method",JsonValue::Number(std::to_string(m.method))); item.Set("flags",JsonValue::Number(std::to_string(m.flags)));
        item.Set("attributes",JsonValue::Number(std::to_string(m.attributes))); list.ArrayItems().push_back(std::move(item));
    }
    out.Set("members",std::move(list)); return out;
}
}
