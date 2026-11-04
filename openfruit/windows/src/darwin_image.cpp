#include "darwin_image.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <bit>
#include <optional>
#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <windows.h>

namespace OpenFruit {
namespace {
constexpr std::uint32_t kX64 = 0x01000007, kArm64 = 0x0100000c;
struct Invalid : std::runtime_error { using std::runtime_error::runtime_error; };
void Check(bool value, const char* text) { if (!value) throw Invalid(text); }
bool Range(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}
std::uint64_t Integer(std::string_view bytes, std::uint64_t offset, unsigned width, bool big = false) {
    Check(Range(offset, width, bytes.size()), "Truncated Mach-O integer.");
    std::uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i)
        result |= std::uint64_t(static_cast<unsigned char>(bytes[static_cast<std::size_t>(offset + i)]))
            << (8 * (big ? width - 1 - i : i));
    return result;
}
std::string CString(std::string_view command, std::uint64_t offset, unsigned minimum) {
    Check(offset >= minimum && offset < command.size(), "Invalid Mach-O string offset.");
    const auto end = command.find('\0', static_cast<std::size_t>(offset));
    Check(end != std::string_view::npos && end > offset, "Unterminated or empty Mach-O string.");
    return std::string(command.substr(static_cast<std::size_t>(offset), end - offset));
}
bool GenericSubtype(std::uint32_t cpu, std::uint32_t subtype) {
    // CPU_SUBTYPE_LIB64 is an ABI capability, not a different CPU instruction set.
    const auto base = subtype & 0x00ffffff;
    return (cpu == kX64 && base == 3 && (subtype & 0x7f000000) == 0) ||
        (cpu == kArm64 && (subtype & 0x7f000000) == 0 && (base == 0 || base == 2));
}
struct Slice { std::uint32_t cpu, subtype; std::uint64_t offset, size; };
std::vector<Slice> Slices(std::string_view bytes) {
    const auto magic = Integer(bytes, 0, 4, true);
    const bool fat32 = magic == 0xcafebabe || magic == 0xbebafeca;
    const bool fat64 = magic == 0xcafebabf || magic == 0xbfbafeca;
    if (!fat32 && !fat64) {
        Check(Integer(bytes, 0, 4) == 0xfeedfacf, "Unsupported image format; requires little-endian Mach-O 64.");
        return {{static_cast<std::uint32_t>(Integer(bytes, 4, 4)),
            static_cast<std::uint32_t>(Integer(bytes, 8, 4)), 0, bytes.size()}};
    }
    const bool big = magic == 0xcafebabe || magic == 0xcafebabf;
    const auto count = Integer(bytes, 4, 4, big);
    const auto stride = fat64 ? 32u : 20u;
    Check(count && count <= 128 && Range(8, count * stride, bytes.size()), "Invalid FAT architecture table.");
    std::vector<Slice> slices;
    for (std::uint64_t i = 0; i < count; ++i) {
        const auto p = 8 + i * stride;
        Slice slice{static_cast<std::uint32_t>(Integer(bytes, p, 4, big)),
            static_cast<std::uint32_t>(Integer(bytes, p + 4, 4, big)),
            Integer(bytes, p + 8, fat64 ? 8 : 4, big),
            Integer(bytes, p + (fat64 ? 16 : 12), fat64 ? 8 : 4, big)};
        const auto alignment = Integer(bytes, p + (fat64 ? 24 : 16), 4, big);
        Check(alignment < 63 && slice.offset >= 8 + count * stride && slice.size >= 32 &&
            Range(slice.offset, slice.size, bytes.size()) &&
            slice.offset % (std::uint64_t{1} << alignment) == 0, "Invalid FAT slice bounds/alignment.");
        if (fat64) Check(Integer(bytes, p + 28, 4, big) == 0, "Invalid FAT reserved field.");
        for (const auto& previous : slices)
            Check(slice.offset >= previous.offset + previous.size || previous.offset >= slice.offset + slice.size,
                "Overlapping FAT slices.");
        slices.push_back(slice);
    }
    return slices;
}
Slice Select(std::string_view bytes, std::uint32_t cpu) {
    const auto slices = Slices(bytes);
    const Slice* selected = nullptr;
    for (const auto& slice : slices) if (slice.cpu == cpu && GenericSubtype(slice.cpu, slice.subtype)) {
        if (!selected) {
            selected = &slice;
        } else {
            const auto prev_base = selected->subtype & 0x00ffffff;
            const auto curr_base = slice.subtype & 0x00ffffff;
            if (prev_base != curr_base) {
                if (curr_base == 2 && prev_base == 0) selected = &slice;
                else if (prev_base == 2 && curr_base == 0) { /* keep selected */ }
                else throw Invalid("Ambiguous compatible FAT slices.");
            } else {
                throw Invalid("Ambiguous compatible FAT slices.");
            }
        }
    }
    Check(selected, "No supported host CPU slice; specialized CPU/ABI variants are unsupported.");
    return *selected;
}
void InspectChains(std::string_view bytes, std::uint64_t file_offset, DarwinImage& image) {
    Check(bytes.size() >= 28 && Integer(bytes, 0, 4) == 0, "Unsupported chained fixups header/version.");
    const auto starts = Integer(bytes, 4, 4), imports = Integer(bytes, 8, 4), symbols = Integer(bytes, 12, 4);
    const auto count = Integer(bytes, 16, 4), format = Integer(bytes, 20, 4);
    Check(Integer(bytes, 24, 4) == 0, "Compressed chained symbol pools are unsupported.");
    Check(format >= 1 && format <= 3 && count <= 262144, "Unsupported chained imports format/count.");
    const auto stride = format == 1 ? 4u : format == 2 ? 8u : 16u;
    Check(starts >= 28 && imports >= 28 && symbols >= 28 && Range(starts, 4, bytes.size())
        && Range(imports, count * stride, bytes.size()) && symbols <= bytes.size(), "Invalid chained table offsets/bounds.");
    DarwinChainedFixups result; result.present = true; result.file_offset = file_offset;
    result.data_size = bytes.size(); result.import_format = static_cast<std::uint32_t>(format);
    const auto segment_count = Integer(bytes, starts, 4);
    Check(segment_count == image.segments.size() && Range(starts + 4, segment_count * 4, bytes.size()), "Invalid chained segment table.");
    std::uint64_t total_pages = 0;
    for (std::uint64_t index = 0; index < segment_count; ++index) {
        const auto relative = Integer(bytes, starts + 4 + index * 4, 4); if (!relative) continue;
        Check(relative >= 4 + segment_count * 4 && Range(starts, relative, bytes.size()), "Invalid chained segment offset.");
        const auto offset = starts + relative, size = Integer(bytes, offset, 4);
        Check(size >= 22 && size % 2 == 0 && Range(offset, size, bytes.size()), "Invalid chained segment size.");
        DarwinChainedSegment segment; segment.segment_index = static_cast<std::uint32_t>(index);
        segment.page_size = static_cast<std::uint16_t>(Integer(bytes, offset + 4, 2));
        segment.pointer_format = static_cast<std::uint16_t>(Integer(bytes, offset + 6, 2));
        segment.segment_offset = Integer(bytes, offset + 8, 8);
        segment.max_valid_pointer = static_cast<std::uint32_t>(Integer(bytes, offset + 16, 4));
        const auto pages = Integer(bytes, offset + 20, 2), entries = (size - 22) / 2;
        Check((segment.page_size == 4096 || segment.page_size == 16384) && segment.pointer_format >= 1
            && segment.pointer_format <= 14 && pages <= entries && entries <= 262144 - total_pages,
            "Invalid chained page table/format or resource limit.");
        total_pages += entries;
        for (std::uint64_t p = 0; p < entries; ++p) {
            const auto entry = static_cast<std::uint16_t>(Integer(bytes, offset + 22 + p * 2, 2));
            if (p < pages) segment.page_starts.push_back(entry); else segment.overflow_starts.push_back(entry);
        }
        for (const auto start : segment.page_starts) {
            if (start == 0xffff) continue;
            if (!(start & 0x8000)) { Check(start < segment.page_size, "Chained start exceeds page."); continue; }
            auto overflow = std::uint64_t(start & 0x7fff);
            Check(overflow >= pages && overflow < entries, "Invalid chained multi-start index.");
            for (;;) {
                Check(overflow < entries, "Unterminated chained multi-start list.");
                const auto value = segment.overflow_starts[static_cast<std::size_t>(overflow++ - pages)];
                Check((value & 0x7fff) < segment.page_size, "Chained overflow start exceeds page.");
                if (value & 0x8000) break;
            }
        }
        result.segments.push_back(std::move(segment));
    }
    std::uint64_t strings = 0;
    for (std::uint64_t index = 0; index < count; ++index) {
        const auto offset = imports + index * stride, bits = Integer(bytes, offset, format == 3 ? 8 : 4);
        const auto ordinal = bits & (format == 3 ? 0xffff : 0xff);
        DarwinChainedImport entry;
        entry.library_ordinal = static_cast<std::int32_t>(ordinal);
        if (ordinal > (format == 3 ? 65520u : 240u)) entry.library_ordinal -= format == 3 ? 65536 : 256;
        entry.weak = ((bits >> (format == 3 ? 16 : 8)) & 1) != 0;
        if (format == 3) Check(((bits >> 17) & 0x7fff) == 0, "Reserved chained import bits are set.");
        const auto name = bits >> (format == 3 ? 32 : 9);
        Check(name < bytes.size() - symbols, "Invalid chained import symbol offset.");
        const auto begin = symbols + name, end = bytes.find('\0', static_cast<std::size_t>(begin));
        Check(end != std::string_view::npos && end > begin && end - begin <= 32768
            && end - begin <= 32ull * 1024 * 1024 - strings, "Invalid chained import string or resource limit.");
        strings += end - begin; entry.symbol = std::string(bytes.substr(static_cast<std::size_t>(begin), end - begin));
        if (format == 2) entry.addend = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(Integer(bytes, offset + 4, 4)));
        if (format == 3) entry.addend = std::bit_cast<std::int64_t>(Integer(bytes, offset + 8, 8));
        Check(entry.library_ordinal >= -3 && (entry.library_ordinal <= 0 ||
            static_cast<std::uint64_t>(entry.library_ordinal) <= image.dependencies.size()), "Invalid chained library ordinal.");
        result.imports.push_back(std::move(entry));
    }
    image.chained_fixups = std::move(result);
}
void WalkChains(std::string_view bytes, DarwinImage& image) {
    auto& fixups = image.chained_fixups;
    if (!fixups.present) return;
    // Other formats remain metadata-only until their pointer semantics exist.
    for (const auto& entry : fixups.segments)
        if (!entry.page_starts.empty() && entry.pointer_format != 2 && entry.pointer_format != 6 && entry.pointer_format != 12) return;
    std::optional<std::uint64_t> base;
    for (const auto& segment : image.segments) if (!segment.file_offset && segment.file_size) {
        Check(!base, "Ambiguous Mach-O header segment."); base = segment.address;
    }
    Check(base.has_value(), "Missing Mach-O header segment.");
    for (const auto& starts : fixups.segments) {
        const auto& segment = image.segments[starts.segment_index];
        Check(segment.address >= *base && starts.segment_offset == segment.address - *base,
            "Chained segment VM offset disagrees with Mach-O segment.");
        Check(starts.page_starts.size() <= segment.size / starts.page_size + (segment.size % starts.page_size != 0),
            "Chained page table exceeds segment VM range.");
        const auto walk = [&](std::uint64_t page, std::uint16_t start) {
            const auto page_begin = page * starts.page_size;
            auto cursor = std::uint64_t(start);
            for (;;) {
                Check((starts.pointer_format == 12 ? cursor % 8 == 0 : cursor % 4 == 0) && Range(cursor, 8, starts.page_size)
                    && Range(page_begin + cursor, 8, segment.file_size)
                    && Range(page_begin + cursor, 8, segment.size), "Chained pointer exceeds original page/segment.");
                Check(fixups.pointers.size() < 1048576, "Chained pointer budget exceeded.");
                DarwinChainedPointer pointer;
                pointer.file_offset = segment.file_offset + page_begin + cursor;
                pointer.address = segment.address + page_begin + cursor;
                const auto bits = Integer(bytes, pointer.file_offset, 8);
                if (starts.pointer_format == 12) {
                    const bool auth = (bits >> 63) != 0;
                    pointer.bind = ((bits >> 62) & 1) != 0;
                    pointer.authenticated = auth;
                    if (!pointer.bind) {
                        if (!auth) {
                            pointer.target = bits & ((1ull << 43) - 1);
                            pointer.high8 = static_cast<std::uint8_t>((bits >> 43) & 0xff);
                            // ARM64E_USERLAND24 stores a runtime VM offset for
                            // unauthenticated rebases as well as authenticated ones.
                            pointer.target_is_offset = true;
                        } else {
                            pointer.target = bits & 0xffffffffull;
                            pointer.diversity = static_cast<std::uint16_t>((bits >> 32) & 0xffff);
                            pointer.address_diversity = ((bits >> 48) & 1) != 0;
                            pointer.key = static_cast<std::uint8_t>((bits >> 49) & 3);
                            pointer.target_is_offset = true;
                        }
                    } else {
                        Check(((bits >> 24) & 0xff) == 0, "Reserved chained bind24 zero bits are set.");
                        pointer.import_index = static_cast<std::uint32_t>(bits & 0xffffff);
                        Check(pointer.import_index < fixups.imports.size(), "Chained bind import index exceeds table.");
                        if (!auth) {
                            std::int64_t addend = (bits >> 32) & 0x7ffff;
                            if (addend & 0x40000) addend -= 0x80000;
                            pointer.addend = addend;
                        } else {
                            pointer.diversity = static_cast<std::uint16_t>((bits >> 32) & 0xffff);
                            pointer.address_diversity = ((bits >> 48) & 1) != 0;
                            pointer.key = static_cast<std::uint8_t>((bits >> 49) & 3);
                        }
                    }
                } else {
                    pointer.bind = (bits >> 63) != 0;
                    pointer.target_is_offset = starts.pointer_format == 6;
                    if (pointer.bind) {
                        Check(((bits >> 32) & 0x7ffff) == 0, "Reserved chained bind bits are set.");
                        pointer.import_index = static_cast<std::uint32_t>(bits & 0xffffff);
                        Check(pointer.import_index < fixups.imports.size(), "Chained bind import index exceeds table.");
                        pointer.addend = static_cast<std::int64_t>((bits >> 24) & 0xff);
                    } else {
                        Check(((bits >> 44) & 0x7f) == 0, "Reserved chained rebase bits are set.");
                        pointer.target = bits & 0xfffffffffull;
                        pointer.high8 = static_cast<std::uint8_t>((bits >> 36) & 0xff);
                    }
                }
                fixups.pointers.push_back(pointer);
                const auto next = starts.pointer_format == 12 ? ((bits >> 51) & 0x7ff) : ((bits >> 51) & 0xfff);
                if (!next) break;
                const auto stride = starts.pointer_format == 12 ? 8u : 4u;
                cursor += next * stride;
            }
        };
        for (std::size_t page = 0; page < starts.page_starts.size(); ++page) {
            const auto start = starts.page_starts[page];
            if (start == 0xffff) continue;
            if (!(start & 0x8000)) { walk(page, start); continue; }
            auto index = static_cast<std::size_t>(start & 0x7fff) - starts.page_starts.size();
            for (;;) {
                Check(index < starts.overflow_starts.size(), "Invalid chained multi-start list.");
                const auto value = starts.overflow_starts[index++]; walk(page, value & 0x7fff);
                if (value & 0x8000) break;
            }
        }
    }
    std::sort(fixups.pointers.begin(), fixups.pointers.end(), [](const auto& left, const auto& right) {
        return left.file_offset < right.file_offset;
    });
    for (std::size_t i = 1; i < fixups.pointers.size(); ++i)
        Check(fixups.pointers[i].file_offset - fixups.pointers[i - 1].file_offset >= 8,
            "Overlapping or repeated chained pointer locations.");
    fixups.pointers_walked = true;
}
std::uint64_t Uleb(std::string_view bytes, std::uint64_t& cursor) {
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        const auto byte = Integer(bytes, cursor++, 1);
        Check(shift != 63 || (byte & 0xfe) == 0, "Export ULEB128 overflow.");
        value |= (byte & 0x7f) << shift;
        if (!(byte & 0x80)) return value;
    }
    throw Invalid("Unterminated export ULEB128.");
}
void InspectExports(std::string_view bytes, DarwinImage& image) {
    if (bytes.empty()) return;
    std::unordered_set<std::uint64_t> active;
    std::unordered_set<std::string> names;
    std::uint64_t nodes = 0, strings = 0;
    const auto visit = [&](const auto& self, std::uint64_t offset, const std::string& prefix, unsigned depth) -> void {
        Check(depth <= 256 && ++nodes <= 1048576 && offset < bytes.size(), "Export trie offset/depth/budget exceeded.");
        Check(active.insert(offset).second, "Cyclic export trie.");
        auto cursor = offset;
        const auto terminal_size = Uleb(bytes, cursor);
        Check(Range(cursor, terminal_size, bytes.size()), "Export terminal exceeds trie bounds.");
        const auto terminal_end = cursor + terminal_size;
        if (terminal_size) {
            const auto payload = bytes.substr(static_cast<std::size_t>(cursor), static_cast<std::size_t>(terminal_size));
            std::uint64_t position = 0;
            DarwinExport symbol; symbol.symbol = prefix;
            Check(!prefix.empty() && names.insert(prefix).second && image.exports.size() < 262144,
                "Empty/duplicate exported symbol or export budget exceeded.");
            Check(prefix.size() <= 32ull * 1024 * 1024 - strings, "Export symbol string budget exceeded.");
            strings += prefix.size();
            symbol.flags = Uleb(payload, position);
            Check((symbol.flags & ~0x3full) == 0 && (symbol.flags & 3) != 3,
                "Unsupported export flags/kind.");
            symbol.value = Uleb(payload, position);
            if (symbol.flags & 8) {
                Check((symbol.flags & (3 | 0x10 | 0x20)) == 0 && symbol.value > 0
                    && symbol.value <= image.dependencies.size(), "Invalid re-export flags/library ordinal.");
                symbol.library_ordinal = static_cast<std::uint32_t>(symbol.value);
                const auto end = payload.find('\0', static_cast<std::size_t>(position));
                Check(end != std::string_view::npos && end - position <= 32768, "Invalid re-export symbol string.");
                symbol.imported_name = end == position ? prefix : std::string(payload.substr(static_cast<std::size_t>(position), end - position));
                Check(symbol.imported_name.size() <= 32ull * 1024 * 1024 - strings, "Re-export string budget exceeded.");
                strings += symbol.imported_name.size(); position = end + 1;
            } else if (symbol.flags & (0x10 | 0x20)) {
                Check((symbol.flags & 3) == 0 && (symbol.flags & 0x30) != 0x30, "Invalid resolver/variant export flags.");
                symbol.auxiliary = Uleb(payload, position);
            }
            Check(position == payload.size(), "Unexpected export terminal payload bytes.");
            image.exports.push_back(std::move(symbol));
        }
        cursor = terminal_end;
        const auto children = Integer(bytes, cursor++, 1);
        for (std::uint64_t i = 0; i < children; ++i) {
            const auto end = bytes.find('\0', static_cast<std::size_t>(cursor));
            Check(end != std::string_view::npos && end > cursor && end - cursor <= 32768
                && prefix.size() <= 32768 - (end - cursor), "Invalid export trie edge string.");
            const auto name = prefix + std::string(bytes.substr(static_cast<std::size_t>(cursor), end - cursor));
            cursor = end + 1;
            const auto child = Uleb(bytes, cursor);
            Check(child != 0, "Invalid zero export child offset.");
            self(self, child, name, depth + 1);
        }
        active.erase(offset);
    };
    visit(visit, 0, {}, 0);
    std::sort(image.exports.begin(), image.exports.end(), [](const auto& left, const auto& right) { return left.symbol < right.symbol; });
}
std::vector<DarwinSection> ParseSections(std::string_view command,const DarwinSegment& segment,bool standalone) {
    Check(command.size()>=72&&Integer(command,0,4)==0x19,"Invalid section owner command.");
    Check(segment.size<=UINT64_MAX-segment.address,"Section owner VM extent overflows.");
    const auto count=Integer(command,64,4);
    Check(count<=65536&&count<=(command.size()-72)/80&&command.size()==72+count*80,"Invalid segment section table.");
    std::vector<DarwinSection> result;result.reserve(static_cast<std::size_t>(count));
    const auto name=[&](std::size_t p){auto value=command.substr(p,16);return std::string(value.substr(0,value.find('\0')));};
    for(std::size_t i=0;i<count;++i){
        const auto p=72+i*80;DarwinSection section;
        section.name=name(p);section.segment_name=name(p+16);
        section.address=Integer(command,p+32,8);section.size=Integer(command,p+40,8);section.file_offset=Integer(command,p+48,4);
        section.alignment=static_cast<std::uint32_t>(Integer(command,p+52,4));
        section.relocation_offset=static_cast<std::uint32_t>(Integer(command,p+56,4));section.relocation_count=static_cast<std::uint32_t>(Integer(command,p+60,4));
        section.flags=static_cast<std::uint32_t>(Integer(command,p+64,4));
        section.reserved1=static_cast<std::uint32_t>(Integer(command,p+68,4));section.reserved2=static_cast<std::uint32_t>(Integer(command,p+72,4));section.reserved3=static_cast<std::uint32_t>(Integer(command,p+76,4));
        Check(section.segment_name==segment.name&&section.address>=segment.address
            &&section.address-segment.address<=segment.size&&section.size<=segment.size-(section.address-segment.address),"Section VM range or owner is invalid.");
        // Cache placement may differ from the original linker's alignment; empty sections have no bytes to align.
        Check(section.alignment<=63&&(!standalone||!section.size
            ||(section.address&((std::uint64_t(1)<<section.alignment)-1))==0),"Section VM alignment is invalid.");
        if(standalone&&!section.ZeroFill()&&section.size) Check(section.file_offset>=segment.file_offset
            &&section.file_offset-segment.file_offset<=segment.file_size
            &&section.size<=segment.file_size-(section.file_offset-segment.file_offset),"Section file range exceeds original segment.");
        result.push_back(std::move(section));
    }
    return result;
}
void InspectThin(std::string_view bytes, DarwinImage& result) {
    Check(Integer(bytes, 0, 4) == 0xfeedfacf, "Unsupported image format; requires little-endian Mach-O 64.");
    const auto cpu = static_cast<std::uint32_t>(Integer(bytes, 4, 4));
    const auto subtype = static_cast<std::uint32_t>(Integer(bytes, 8, 4));
    Check(cpu == result.cpu && GenericSubtype(cpu, subtype), "Mach-O CPU/ABI does not match the supported host slice.");
    if (result.slice_offset) Check(subtype == result.subtype, "FAT and Mach-O CPU subtype disagree.");
    result.subtype = subtype;
    result.file_type = static_cast<std::uint32_t>(Integer(bytes, 12, 4));
    result.header_flags = static_cast<std::uint32_t>(Integer(bytes, 24, 4));
    Check(result.file_type == 2 || result.file_type == 6 || result.file_type == 7 || result.file_type == 8,
        "Mach-O file type is not a runtime executable/library/bundle.");
    const auto count = Integer(bytes, 16, 4), length = Integer(bytes, 20, 4);
    Check(count && count <= 65536 && count <= length / 8 && Range(32, length, bytes.size()), "Invalid or unsupported Mach-O load-command table.");
    Check(Integer(bytes, 28, 4) == 0, "Invalid Mach-O reserved header field.");
    std::uint64_t offset = 32;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> chains;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> exports;
    std::optional<std::string_view> unix_thread;
    for (std::uint64_t i = 0; i < count; ++i) {
        Check(Range(offset, 8, 32 + length), "Truncated Mach-O load command.");
        const auto kind = static_cast<std::uint32_t>(Integer(bytes, offset, 4));
        const auto size = Integer(bytes, offset + 4, 4);
        Check(size >= 8 && size % 8 == 0 && Range(offset, size, 32 + length), "Invalid Mach-O load-command size.");
        const auto command = bytes.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(size));
        if (kind & 0x80000000) result.required_commands.push_back(kind);
        if (kind == 0xc || kind == 0xd || kind == 0x80000018 || kind == 0x8000001f || kind == 0x20 || kind == 0x80000023) {
            Check(size >= 24, "Truncated dylib command.");
            const auto name = CString(command, Integer(command, 8, 4), 24);
            if (kind == 0xd) {
                Check(result.install_name.empty(), "Duplicate dylib identity."); result.install_name = name;
            } else result.dependencies.push_back({name, kind == 0x80000018, kind == 0x8000001f,
                kind == 0x80000023, kind == 0x20});
        } else if (kind == 0x8000001c || kind == 0xe || kind == 0xf) {
            Check(size >= (kind == 0xf ? 12 : 16), "Truncated path command.");
            const auto name = CString(command, Integer(command, 8, 4), 12);
            if (kind == 0xe) { Check(result.interpreter.empty(), "Duplicate dynamic linker."); result.interpreter = name; }
            else if (kind == 0xf) { Check(result.install_name.empty(), "Duplicate dynamic linker identity."); result.install_name = name; }
            else result.rpaths.push_back(name);
        } else if (kind == 0x19) {
            Check(size >= 72, "Truncated segment command.");
            const auto sections = Integer(command, 64, 4);
            Check(sections <= (size - 72) / 80 && size == 72 + sections * 80, "Invalid segment section table.");
            auto name = command.substr(8, 16); name = name.substr(0, name.find('\0'));
            DarwinSegment segment{std::string(name), Integer(command, 24, 8), Integer(command, 32, 8),
                Integer(command, 40, 8), Integer(command, 48, 8),
                static_cast<std::uint32_t>(Integer(command, 56, 4)), static_cast<std::uint32_t>(Integer(command, 60, 4))};
            Check(segment.size <= std::numeric_limits<std::uint64_t>::max() - segment.address &&
                segment.file_size <= segment.size && Range(segment.file_offset, segment.file_size, bytes.size()),
                "Invalid segment VM/file bounds.");
            Check((segment.maximum_protection & ~7u) == 0 &&
                (segment.initial_protection & ~segment.maximum_protection) == 0, "Invalid segment protections.");
            for (const auto& previous : result.segments) if (segment.size && previous.size)
                Check(segment.address >= previous.address + previous.size || previous.address >= segment.address + segment.size,
                    "Overlapping Mach-O virtual segments.");
            auto original_sections=ParseSections(command,segment,true);
            Check(original_sections.size()<=65536-result.sections.size(),"Mach-O section count budget exceeded.");
            for(auto& section:original_sections){
                if(section.relocation_count){
                    Check(Range(section.relocation_offset,std::uint64_t(section.relocation_count)*8,bytes.size()),"Section relocation table exceeds file.");
                    result.legacy_fixups_required=true;
                }
                result.sections.push_back(std::move(section));
            }
            result.segments.push_back(std::move(segment));
        } else if (kind == 0xb) {
            Check(size == 80, "Invalid dynamic symbol table command.");
            if (Integer(command, 68, 4) || Integer(command, 76, 4)) result.legacy_fixups_required = true;
        } else if (kind == 0x32) {
            Check(size >= 24 && Integer(command, 20, 4) <= (size - 24) / 8 &&
                size == 24 + Integer(command, 20, 4) * 8, "Invalid build-version command.");
            const auto platform = static_cast<std::uint32_t>(Integer(command, 8, 4));
            // A zippered image declares macOS (1) and Mac Catalyst (6); a macOS
            // process loads it as macOS. Any other second platform is invalid.
            Check(!result.platform || (result.platform != platform && (result.platform == 1 || platform == 1) &&
                (result.platform == 6 || platform == 6)), "Duplicate platform command.");
            result.platform = result.platform ? 1 : platform;
        } else if (kind == 0x24 || kind == 0x25 || kind == 0x2f || kind == 0x30) {
            Check(size == 16 && !result.platform, "Invalid or duplicate minimum-version command.");
            result.platform = kind == 0x24 ? 1 : kind == 0x25 ? 2 : kind == 0x2f ? 3 : 4;
        } else if (kind == 0x22 || kind == 0x80000022) {
            Check(size == 48, "Invalid dyld-info command.");
            for (unsigned p = 12; p < 40; p += 8) if (Integer(command, p, 4)) result.legacy_fixups_required = true;
            for (unsigned p = 8; p < 48; p += 8)
                Check(Range(Integer(command, p, 4), Integer(command, p + 4, 4), bytes.size()), "Invalid dyld-info data bounds.");
            if (Integer(command, 44, 4)) {
                Check(!exports, "Ambiguous export trie commands.");
                exports = std::pair{Integer(command, 40, 4), Integer(command, 44, 4)};
            }
        } else if (kind == 0x80000034 || kind == 0x80000033 || kind == 0x1d || kind == 0x26 || kind == 0x29) {
            Check(size == 16 && Range(Integer(command, 8, 4), Integer(command, 12, 4), bytes.size()), "Invalid linkedit data bounds.");
            if (kind == 0x80000034) {
                Check(!chains, "Duplicate chained fixups command.");
                chains = std::pair{Integer(command, 8, 4), Integer(command, 12, 4)};
            }
            if (kind == 0x80000033) {
                Check(!exports, "Ambiguous export trie commands.");
                exports = std::pair{Integer(command, 8, 4), Integer(command, 12, 4)};
            }
        } else if (kind == 0x80000028) {
            Check(size==24&&result.file_type==2&&!result.entrypoint.present&&Integer(command,8,8)<bytes.size(),"Invalid or duplicate main entrypoint command.");
            result.entrypoint={true,Integer(command,8,8),0,Integer(command,16,8)};
        } else if(kind==5) {
            Check(!unix_thread,"Duplicate Unix thread command.");unix_thread=command;
        }
        offset += size;
    }
    Check(offset == 32 + length, "Mach-O load-command count/size disagree.");
    Check(!result.segments.empty(), "Runtime Mach-O image has no segments.");
    Check(!unix_thread||!result.entrypoint.present,"Conflicting main and Unix thread entrypoints.");
    if(unix_thread){std::string error;if(!InspectDarwinUnixThread(*unix_thread,result,result.unix_thread,error))throw Invalid(error);}
    if(result.entrypoint.present){
        const auto segment=std::find_if(result.segments.begin(),result.segments.end(),[&](const auto& candidate){
            return (candidate.initial_protection&4)&&result.entrypoint.file_offset>=candidate.file_offset
                &&result.entrypoint.file_offset-candidate.file_offset<candidate.file_size;
        });
        Check(segment!=result.segments.end(),"Main entrypoint is not in original executable file bytes.");
        result.entrypoint.address=segment->address+result.entrypoint.file_offset-segment->file_offset;
    }
    if (exports) {
        result.exports_present = true; result.exports_file_offset = exports->first; result.exports_data_size = exports->second;
        InspectExports(bytes.substr(static_cast<std::size_t>(exports->first), static_cast<std::size_t>(exports->second)), result);
    }
    if (chains) {
        InspectChains(bytes.substr(static_cast<std::size_t>(chains->first), static_cast<std::size_t>(chains->second)), chains->first, result);
        WalkChains(bytes, result);
    }
}
struct Handle { HANDLE value = nullptr; ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct View { void* address = nullptr; ~View() { if (address) UnmapViewOfFile(address); } };
}
std::uint32_t DarwinProcessCpu() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return kX64;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return kArm64;
#else
    return 0;
#endif
}
JsonValue DarwinUnixThread::ToJson() const {
    auto value=JsonValue::ObjectValue(),words=JsonValue::ArrayValue();
    value.Set("present",JsonValue::Boolean(present));
    value.Set("flavor",JsonValue::Number(std::to_string(flavor)));
    value.Set("pc",JsonValue::Number(std::to_string(pc)));value.Set("sp",JsonValue::Number(std::to_string(sp)));
    for(const auto word:state_words)words.ArrayItems().push_back(JsonValue::Number(std::to_string(word)));
    value.Set("state_words",std::move(words));return value;
}
bool InspectDarwinUnixThread(std::string_view command,const DarwinImage& owner,DarwinUnixThread& output,std::string& error){
    output={};error.clear();try{
        Check(owner.file_type==2||owner.file_type==7,"Unix thread command requires executable/interpreter image.");
        Check(command.size()>=16&&Integer(command,0,4)==5&&Integer(command,4,4)==command.size(),"Invalid Unix thread command bounds.");
        const auto arm=owner.cpu==kArm64;Check(arm||owner.cpu==kX64,"Unsupported Unix thread CPU.");
        const auto count=arm?68u:42u,flavor=arm?6u:4u;
        Check(Integer(command,8,4)==flavor&&Integer(command,12,4)==count&&command.size()==16+count*4,
            "Unsupported or malformed Unix thread state flavor/count.");
        DarwinUnixThread state;state.present=true;state.flavor=flavor;
        for(std::size_t p=16;p<command.size();p+=4)state.state_words.push_back(static_cast<std::uint32_t>(Integer(command,p,4)));
        state.pc=Integer(command,16+(arm?32:16)*8,8);state.sp=Integer(command,16+(arm?31:7)*8,8);
        Check(state.pc&&(!arm||state.pc%4==0),"Unix thread entrypoint alignment is invalid.");
        const auto executable=std::find_if(owner.segments.begin(),owner.segments.end(),[&](const auto& segment){
            return (segment.initial_protection&4)&&state.pc>=segment.address&&state.pc-segment.address<segment.file_size;
        });
        Check(executable!=owner.segments.end(),"Unix thread entrypoint is not in original executable bytes.");
        output=std::move(state);return true;
    }catch(const std::exception& failure){error=failure.what();return false;}
}
bool InspectDarwinSegmentSections(std::string_view command,const DarwinSegment& segment,bool standalone,
    std::vector<DarwinSection>& result,std::string& error){
    result.clear();error.clear();try{result=ParseSections(command,segment,standalone);return true;}
    catch(const Invalid& failure){error=failure.what();return false;}
}
JsonValue DarwinSection::ToJson() const {
    auto value=JsonValue::ObjectValue();value.Set("name",JsonValue::String(name));value.Set("segment_name",JsonValue::String(segment_name));
    for(const auto& [key,number]:std::vector<std::pair<const char*,std::uint64_t>>{
        {"address",address},{"size",size},{"file_offset",file_offset},{"alignment",alignment},{"flags",flags},
        {"relocation_offset",relocation_offset},{"relocation_count",relocation_count},{"reserved1",reserved1},{"reserved2",reserved2},{"reserved3",reserved3}})
        value.Set(key,JsonValue::Number(std::to_string(number)));
    value.Set("zero_fill",JsonValue::Boolean(ZeroFill()));return value;
}
bool InspectDarwinExportTrie(std::string_view bytes,const std::vector<DarwinDependency>& dependencies,std::vector<DarwinExport>& result,std::string& error){
    result.clear();error.clear();try{Check(bytes.size()<=16ull*1024*1024&&dependencies.size()<=65536,"Original export trie input budget exceeded.");DarwinImage owner;owner.dependencies=dependencies;InspectExports(bytes,owner);result=std::move(owner.exports);return true;}catch(const Invalid& failure){error=failure.what();return false;}
}
bool InspectDarwinImage(std::string_view bytes, std::uint32_t cpu, DarwinImage& result, std::string& error) {
    result = {}; error.clear();
    try {
        Check(cpu == kX64 || cpu == kArm64, "Unsupported process CPU.");
        const auto slice = Select(bytes, cpu);
        DarwinImage candidate;
        candidate.cpu = cpu; candidate.subtype = slice.subtype;
        candidate.slice_offset = slice.offset; candidate.slice_size = slice.size;
        InspectThin(bytes.substr(static_cast<std::size_t>(slice.offset), static_cast<std::size_t>(slice.size)), candidate);
        result = std::move(candidate); return true;
    } catch (const Invalid& failure) { error = failure.what(); return false; }
}
bool InspectDarwinImageSlices(std::string_view bytes, std::vector<DarwinImage>& result, std::string& error) {
    result.clear(); error.clear();
    try {
        const auto slices = Slices(bytes);
        std::vector<DarwinImage> candidate;
        for (const auto& slice : slices) {
            Check(GenericSubtype(slice.cpu, slice.subtype), "Unsupported CPU/ABI variant in image inventory.");
            Check(std::none_of(candidate.begin(), candidate.end(), [&](const auto& prior) { return prior.cpu == slice.cpu; }),
                "Ambiguous compatible FAT slices.");
            DarwinImage image; image.cpu = slice.cpu; image.subtype = slice.subtype;
            image.slice_offset = slice.offset; image.slice_size = slice.size;
            InspectThin(bytes.substr(static_cast<std::size_t>(slice.offset), static_cast<std::size_t>(slice.size)), image);
            candidate.push_back(std::move(image));
        }
        result = std::move(candidate); return true;
    } catch (const Invalid& failure) { error = failure.what(); return false; }
}
namespace {
template<class Consumer>
bool ReadSnapshot(const std::filesystem::path& path, std::string& error, Consumer consumer) {
    Handle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    LARGE_INTEGER size{};
    if (file.value == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.value, &size)) {
        error = "Cannot open stable Darwin image (Win32 " + std::to_string(GetLastError()) + ")."; return false;
    }
    if (size.QuadPart < 32 || size.QuadPart > 512ll * 1024 * 1024) { error = "Darwin image size is unsupported."; return false; }
    Handle mapping{CreateFileMappingW(file.value, nullptr, PAGE_READONLY, 0, 0, nullptr)};
    if (!mapping.value) { error = "Cannot map Darwin image read-only."; return false; }
    View view{MapViewOfFile(mapping.value, FILE_MAP_READ, 0, 0, 0)};
    if (!view.address) { error = "Cannot read Darwin image mapping."; return false; }
    const std::string_view bytes(static_cast<const char*>(view.address), static_cast<std::size_t>(size.QuadPart));
    return consumer(bytes);
}
}
bool ReadDarwinImage(const std::filesystem::path& path, std::uint32_t cpu, DarwinImage& result, std::string& error) {
    result = {}; error.clear();
    return ReadSnapshot(path, error, [&](std::string_view bytes) {
        DarwinImage candidate;
        if (!InspectDarwinImage(bytes, cpu, candidate, error)) return false;
        const auto hash = Sha256(bytes);
        if (!hash) { error = "Darwin image hash failed."; return false; }
        candidate.sha256 = *hash; result = std::move(candidate); return true;
    });
}
bool ReadDarwinImage(const std::filesystem::path& path, DarwinImage& result, std::string& error) {
    return ReadDarwinImage(path, DarwinProcessCpu(), result, error);
}
bool ReadDarwinImageSlices(const std::filesystem::path& path, std::vector<DarwinImage>& result, std::string& error) {
    result.clear(); error.clear();
    return ReadSnapshot(path, error, [&](std::string_view bytes) {
        std::vector<DarwinImage> candidate;
        if (!InspectDarwinImageSlices(bytes, candidate, error)) return false;
        const auto hash = Sha256(bytes);
        if (!hash) { error = "Darwin image hash failed."; return false; }
        for (auto& image : candidate) image.sha256 = *hash;
        result = std::move(candidate); return true;
    });
}
JsonValue DarwinImage::ToJson() const {
    auto value = JsonValue::ObjectValue(), paths = JsonValue::ArrayValue(), imports = JsonValue::ArrayValue();
    value.Set("sha256", JsonValue::String(sha256));
    value.Set("cpu", JsonValue::Number(std::to_string(cpu)));
    value.Set("subtype", JsonValue::Number(std::to_string(subtype)));
    value.Set("file_type", JsonValue::Number(std::to_string(file_type)));
    value.Set("header_flags", JsonValue::Number(std::to_string(header_flags)));
    value.Set("platform", JsonValue::Number(std::to_string(platform)));
    auto original_sections=JsonValue::ArrayValue();for(const auto& section:sections)original_sections.ArrayItems().push_back(section.ToJson());
    value.Set("sections",std::move(original_sections));
    auto main_entry=JsonValue::ObjectValue();main_entry.Set("present",JsonValue::Boolean(entrypoint.present));
    main_entry.Set("file_offset",JsonValue::Number(std::to_string(entrypoint.file_offset)));main_entry.Set("address",JsonValue::Number(std::to_string(entrypoint.address)));
    main_entry.Set("stack_size",JsonValue::Number(std::to_string(entrypoint.stack_size)));value.Set("entrypoint",std::move(main_entry));
    value.Set("unix_thread",unix_thread.ToJson());
    value.Set("slice_offset", JsonValue::Number(std::to_string(slice_offset)));
    value.Set("slice_size", JsonValue::Number(std::to_string(slice_size)));
    value.Set("install_name", JsonValue::String(install_name));
    value.Set("interpreter", JsonValue::String(interpreter));
    value.Set("process_cpu_matches", JsonValue::Boolean(cpu == DarwinProcessCpu()));
    for (const auto& path : rpaths) paths.ArrayItems().push_back(JsonValue::String(path));
    for (const auto& dependency : dependencies) {
        auto item = JsonValue::ObjectValue(); item.Set("install_name", JsonValue::String(dependency.install_name));
        item.Set("weak", JsonValue::Boolean(dependency.weak)); item.Set("reexport", JsonValue::Boolean(dependency.reexport));
        item.Set("upward", JsonValue::Boolean(dependency.upward)); item.Set("lazy", JsonValue::Boolean(dependency.lazy));
        imports.ArrayItems().push_back(std::move(item));
    }
    value.Set("rpaths", std::move(paths)); value.Set("dependencies", std::move(imports));
    auto commands = JsonValue::ArrayValue();
    for (const auto command : required_commands) commands.ArrayItems().push_back(JsonValue::Number(std::to_string(command)));
    value.Set("required_commands", std::move(commands));
    auto fixups = JsonValue::ObjectValue(), chain_imports = JsonValue::ArrayValue(), starts = JsonValue::ArrayValue();
    fixups.Set("present", JsonValue::Boolean(chained_fixups.present));
    fixups.Set("file_offset", JsonValue::Number(std::to_string(chained_fixups.file_offset)));
    fixups.Set("data_size", JsonValue::Number(std::to_string(chained_fixups.data_size)));
    fixups.Set("import_format", JsonValue::Number(std::to_string(chained_fixups.import_format)));
    fixups.Set("applied", JsonValue::Boolean(false));
    fixups.Set("pointers_walked", JsonValue::Boolean(chained_fixups.pointers_walked));
    const auto binds = std::count_if(chained_fixups.pointers.begin(), chained_fixups.pointers.end(), [](const auto& pointer) { return pointer.bind; });
    fixups.Set("bind_pointer_count", JsonValue::Number(std::to_string(binds)));
    fixups.Set("rebase_pointer_count", JsonValue::Number(std::to_string(chained_fixups.pointers.size() - binds)));
    for (const auto& entry : chained_fixups.imports) {
        auto item = JsonValue::ObjectValue(); item.Set("symbol", JsonValue::String(entry.symbol));
        item.Set("library_ordinal", JsonValue::Number(std::to_string(entry.library_ordinal)));
        item.Set("weak", JsonValue::Boolean(entry.weak)); item.Set("addend", JsonValue::Number(std::to_string(entry.addend)));
        item.Set("dependency_install_name", JsonValue::String(entry.library_ordinal > 0 ? dependencies[entry.library_ordinal - 1].install_name : ""));
        chain_imports.ArrayItems().push_back(std::move(item));
    }
    for (const auto& entry : chained_fixups.segments) {
        auto item = JsonValue::ObjectValue(), pages = JsonValue::ArrayValue(), overflow = JsonValue::ArrayValue();
        item.Set("segment_index", JsonValue::Number(std::to_string(entry.segment_index)));
        item.Set("page_size", JsonValue::Number(std::to_string(entry.page_size)));
        item.Set("pointer_format", JsonValue::Number(std::to_string(entry.pointer_format)));
        item.Set("segment_offset", JsonValue::Number(std::to_string(entry.segment_offset)));
        for (const auto page : entry.page_starts) pages.ArrayItems().push_back(JsonValue::Number(std::to_string(page)));
        for (const auto page : entry.overflow_starts) overflow.ArrayItems().push_back(JsonValue::Number(std::to_string(page)));
        item.Set("page_starts", std::move(pages)); item.Set("overflow_starts", std::move(overflow)); starts.ArrayItems().push_back(std::move(item));
    }
    fixups.Set("imports", std::move(chain_imports)); fixups.Set("segments", std::move(starts)); value.Set("chained_fixups", std::move(fixups));
    auto exports = JsonValue::ObjectValue();
    exports.Set("present", JsonValue::Boolean(exports_present));
    exports.Set("file_offset", JsonValue::Number(std::to_string(exports_file_offset)));
    exports.Set("data_size", JsonValue::Number(std::to_string(exports_data_size)));
    exports.Set("symbol_count", JsonValue::Number(std::to_string(this->exports.size())));
    exports.Set("addresses_resolved", JsonValue::Boolean(false));
    value.Set("export_trie", std::move(exports));
    return value;
}
DarwinImageInventory DarwinImageInventory::Inspect(const std::filesystem::path& path) {
    DarwinImageInventory result; result.path = path;
    result.inspected = ReadDarwinImageSlices(path, result.images, result.error); return result;
}
JsonValue DarwinImageInventory::ToJson() const {
    auto value = JsonValue::ObjectValue(), entries = JsonValue::ArrayValue();
    value.Set("schema_version", JsonValue::Number("1"));
    value.Set("path", JsonValue::String(Win32Process::ToNarrow(path.wstring())));
    value.Set("metadata_inspected", JsonValue::Boolean(inspected));
    value.Set("process_cpu", JsonValue::Number(std::to_string(DarwinProcessCpu())));
    value.Set("execution_validated", JsonValue::Boolean(false));
    value.Set("closure_complete", JsonValue::Boolean(false));
    value.Set("diagnostic", JsonValue::String(error));
    for (const auto& image : images) entries.ArrayItems().push_back(image.ToJson());
    value.Set("images", std::move(entries)); return value;
}
}
