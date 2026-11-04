#pragma once
#include "json_value.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace OpenFruit {
struct DarwinDependency {
    std::string install_name;
    bool weak = false, reexport = false, upward = false, lazy = false;
};
struct DarwinSegment {
    std::string name;
    std::uint64_t address = 0, size = 0, file_offset = 0, file_size = 0;
    std::uint32_t maximum_protection = 0, initial_protection = 0;
};
struct DarwinSection {
    std::string name, segment_name;
    std::uint64_t address = 0, size = 0, file_offset = 0;
    std::uint32_t alignment = 0, flags = 0, relocation_offset = 0, relocation_count = 0;
    std::uint32_t reserved1 = 0, reserved2 = 0, reserved3 = 0;
    bool ZeroFill() const noexcept { const auto kind=flags&255; return kind==1||kind==12||kind==18; }
    JsonValue ToJson() const;
};
struct DarwinEntryPoint {
    bool present = false;
    std::uint64_t file_offset = 0, address = 0, stack_size = 0;
};
struct DarwinUnixThread {
    bool present = false;
    std::uint32_t flavor = 0;
    std::uint64_t pc = 0, sp = 0;
    std::vector<std::uint32_t> state_words;
    JsonValue ToJson() const;
};
// Shared original section-table parser. Cache consumers use VM geometry;
// standalone consumers additionally validate the original segment file layout.
bool InspectDarwinSegmentSections(std::string_view, const DarwinSegment&, bool standalone,
    std::vector<DarwinSection>&, std::string& error);
struct DarwinChainedImport {
    std::string symbol;
    std::int32_t library_ordinal = 0;
    std::int64_t addend = 0;
    bool weak = false;
};
struct DarwinChainedSegment {
    std::uint32_t segment_index = 0, max_valid_pointer = 0;
    std::uint16_t page_size = 0, pointer_format = 0;
    std::uint64_t segment_offset = 0;
    std::vector<std::uint16_t> page_starts, overflow_starts;
};
struct DarwinChainedPointer {
    // Offsets refer to the selected thin slice and its original VM layout.
    std::uint64_t file_offset = 0, address = 0, target = 0;
    std::int64_t addend = 0;
    std::uint32_t import_index = 0;
    std::uint16_t diversity = 0;
    std::uint8_t high8 = 0, key = 0;
    bool bind = false, target_is_offset = false;
    bool authenticated = false, address_diversity = false;
};
struct DarwinExport {
    std::string symbol, imported_name;
    std::uint64_t flags = 0, value = 0, auxiliary = 0;
    std::uint32_t library_ordinal = 0;
};
struct DarwinChainedFixups {
    bool present = false;
    bool pointers_walked = false;
    std::uint64_t file_offset = 0, data_size = 0;
    std::uint32_t import_format = 0;
    std::vector<DarwinChainedImport> imports;
    std::vector<DarwinChainedSegment> segments;
    std::vector<DarwinChainedPointer> pointers;
};
struct DarwinImage {
    std::uint32_t cpu = 0, subtype = 0, file_type = 0, platform = 0, header_flags = 0;
    std::uint64_t slice_offset = 0, slice_size = 0;
    // Exact original VM header for shared-cache images (not a file offset).
    std::uint64_t cache_header_address = 0;
    std::string install_name, interpreter, sha256;
    std::vector<std::string> rpaths;
    std::vector<DarwinDependency> dependencies;
    std::vector<DarwinSegment> segments;
    std::vector<DarwinSection> sections;
    DarwinEntryPoint entrypoint;
    DarwinUnixThread unix_thread;
    std::vector<std::uint32_t> required_commands;
    DarwinChainedFixups chained_fixups;
    bool exports_present = false;
    bool legacy_fixups_required = false;
    std::uint64_t exports_file_offset = 0, exports_data_size = 0;
    std::vector<DarwinExport> exports;
    JsonValue ToJson() const;
};
// Original LC_UNIXTHREAD, shared by standalone and cache VM readers.
bool InspectDarwinUnixThread(std::string_view,const DarwinImage&,DarwinUnixThread&,std::string& error);
// Parse original trie bytes with dependency ordinals derived from their owner.
bool InspectDarwinExportTrie(std::string_view,const std::vector<DarwinDependency>&,
    std::vector<DarwinExport>&,std::string& error);
// Metadata only: no mapping/execution, fixup application, symbol resolution,
// runtime availability or ABI validation. Unsupported CPU variants fail closed.
std::uint32_t DarwinProcessCpu() noexcept;
bool InspectDarwinImage(std::string_view bytes, std::uint32_t cpu, DarwinImage& result, std::string& error);
// Stable read-only mapping denies concurrent writes/replacement during parsing
bool ReadDarwinImage(const std::filesystem::path&, DarwinImage& result, std::string& error);
bool ReadDarwinImage(const std::filesystem::path&, std::uint32_t cpu, DarwinImage& result, std::string& error);
// All declared generic x86_64/ARM64 slices, atomically inspected as metadata.
// Never changes runtime host selection or implies foreign-ISA execution.
bool InspectDarwinImageSlices(std::string_view bytes, std::vector<DarwinImage>&, std::string& error);
bool ReadDarwinImageSlices(const std::filesystem::path&, std::vector<DarwinImage>&, std::string& error);
struct DarwinImageInventory {
    std::filesystem::path path;
    std::vector<DarwinImage> images;
    std::string error;
    bool inspected = false;
    static DarwinImageInventory Inspect(const std::filesystem::path&);
    JsonValue ToJson() const;
};
}
