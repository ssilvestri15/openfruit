#include "darwin_image.hpp"
#include "darwin_mapping.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
void Put(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned width) {
    Require(offset <= bytes.size() && width <= bytes.size() - offset, "Owned fixture write out of range");
    for (unsigned n = 0; n < width; ++n) bytes[offset + n] = static_cast<char>(value >> (8 * n));
}
void Write(const fs::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(bool(output), "Owned fixture file write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    Require(bool(input), "Owned fixture file read failed");
    return {std::istreambuf_iterator<char>(input), {}};
}
struct TemporaryTree {
    fs::path root;
    TemporaryTree() {
        root = fs::temp_directory_path() / ("openfruit-tagged-rebase-" + std::to_string(GetCurrentProcessId())
            + "-" + std::to_string(GetTickCount64()));
        Require(fs::create_directory(root), "Unique owned fixture directory unavailable");
        fs::create_directory(root / "owned");
    }
    ~TemporaryTree() { std::error_code ignored; fs::remove_all(root, ignored); }
};
constexpr std::uint64_t Base = 0x100000000ull;
constexpr std::uint64_t Target = 0x2200;
constexpr std::uint64_t Payload = 0x1122334455667788ull;
constexpr std::array<std::uint8_t, 4> Tags{0, 1, 0xab, 0xff};
constexpr std::size_t DataFile = 0x1000, ChainsFile = 0x2000, Starts = ChainsFile + 28;
constexpr std::size_t SegmentStarts = Starts + 16;

// OPENFRUIT-owned, dependency-free ARM64 Mach-O. Nothing is copied from an
// Apple binary. The fields follow Apple's published fixup-chains.h:
// https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h
// Three segments deliberately leave a VM hole [base+0x1000, base+0x2000).
// Formats 6 and 12 use offsets even with a nonzero preferred image base.
std::string Fixture(std::uint16_t format, std::uint64_t target = Target, bool readable_target = true) {
    Require(format == 2 || format == 6 || format == 12, "Unassigned pointer format");
    std::string bytes(0x3000, '\0');
    Put(bytes, 0, 0xfeedfacf, 4); Put(bytes, 4, 0x0100000c, 4);
    Put(bytes, 12, 6, 4); // MH_DYLIB, no dependency/interpreter needed for mapping.
    Put(bytes, 16, 5, 4); Put(bytes, 20, 3 * 72 + 24 + 16, 4);
    const auto segment = [&](std::size_t command, const char* name, std::uint64_t offset,
        std::uint64_t file, std::uint32_t protection) {
        Put(bytes, command, 0x19, 4); Put(bytes, command + 4, 72, 4);
        std::memcpy(bytes.data() + command + 8, name, std::strlen(name));
        Put(bytes, command + 24, Base + offset, 8); Put(bytes, command + 32, 0x1000, 8);
        Put(bytes, command + 40, file, 8); Put(bytes, command + 48, 0x1000, 8);
        Put(bytes, command + 56, 7, 4); Put(bytes, command + 60, protection, 4);
    };
    segment(32, "__TEXT", 0, 0, 5);
    segment(104, "__DATA", 0x2000, DataFile, readable_target ? 3 : 0);
    segment(176, "__LINKEDIT", 0x3000, ChainsFile, 1);
    Put(bytes, 248, 0x32, 4); Put(bytes, 252, 24, 4); // LC_BUILD_VERSION
    Put(bytes, 256, 1, 4); Put(bytes, 260, 13 << 16, 4); Put(bytes, 264, 13 << 16, 4);
    Put(bytes, 272, 0x80000034, 4); Put(bytes, 276, 16, 4);
    Put(bytes, 280, ChainsFile, 4); Put(bytes, 284, 68, 4);
    Put(bytes, ChainsFile + 4, 28, 4); // starts_offset
    Put(bytes, ChainsFile + 8, 68, 4); Put(bytes, ChainsFile + 12, 68, 4);
    Put(bytes, ChainsFile + 20, 1, 4); // empty DYLD_CHAINED_IMPORT table
    Put(bytes, Starts, 3, 4); Put(bytes, Starts + 8, 16, 4); // __DATA starts
    Put(bytes, SegmentStarts, 24, 4); Put(bytes, SegmentStarts + 4, 4096, 2);
    Put(bytes, SegmentStarts + 6, format, 2); Put(bytes, SegmentStarts + 8, 0x2000, 8);
    Put(bytes, SegmentStarts + 20, 1, 2); // one page, start offset zero
    for (std::size_t n = 0; n < Tags.size(); ++n) {
        const auto encoded_target = format == 2 ? Base + target : target;
        const auto high8 = std::uint64_t(Tags[n]) << (format == 12 ? 43 : 36);
        const auto next = n + 1 == Tags.size() ? 0ull : format == 12 ? 1ull : 2ull;
        Put(bytes, DataFile + n * 8, encoded_target | high8 | (next << 51), 8);
    }
    Put(bytes, DataFile + 0x200, Payload, 8);
    return bytes;
}
void TagFirstRebase(std::string& bytes, std::uint16_t format) {
    std::uint64_t word = 0;
    std::memcpy(&word, bytes.data() + DataFile, 8);
    Put(bytes, DataFile, word | (0xffull << (format == 12 ? 43 : 36)), 8);
}
void CheckUnchanged(const fs::path& path, const std::string& bytes, const std::string& hash) {
    Require(Read(path) == bytes && Sha256File(path) == hash, "Mapping changed owned original source bytes/hash");
}
void MapsTaggedTargets(const fs::path& tree, std::uint16_t format) {
    const auto path = tree / "owned" / "image.dylib";
    const auto bytes = Fixture(format); Write(path, bytes);
    DarwinImage metadata; std::string error;
    Require(ReadDarwinImage(path, 0x0100000c, metadata, error), "Fixture decode failed: " + error);
    Require(metadata.chained_fixups.pointers_walked && metadata.chained_fixups.pointers.size() == Tags.size(),
        "Original chain did not decode all four pointer slots");
    Require(metadata.chained_fixups.imports.empty(), "Rebase fixture unexpectedly imports symbols");
    const auto hash = Sha256(bytes); Require(bool(hash) && metadata.sha256 == *hash, "Source identity not captured");
    for (std::size_t n = 0; n < Tags.size(); ++n) {
        const auto& pointer = metadata.chained_fixups.pointers[n];
        Require(!pointer.bind && !pointer.authenticated && pointer.high8 == Tags[n]
            && pointer.address == Base + 0x2000 + n * 8 && pointer.file_offset == DataFile + n * 8
            && pointer.target == (format == 2 ? Base + Target : Target)
            && pointer.target_is_offset == (format != 2), "Apple rebase encoding/target kind decoded incorrectly");
    }
    auto mapped = DarwinMappedImages::Load("/owned/image.dylib", {tree}, error, {}, DarwinMappingMode::Arm64Guest);
    Require(bool(mapped), "Tagged original chain could not be mapped: " + error);
    Require(mapped->ImageCount() == 1 && mapped->AppliedFixups() == Tags.size(), "Incorrect mapped fixup count");
    const auto ranges = mapped->Ranges();
    const auto data = std::find_if(ranges.begin(), ranges.end(), [](const auto& range) { return range.protection == 3; });
    Require(data != ranges.end() && data->host_bytes && data->size == 0x1000, "Owned data mapping missing");
    std::uint64_t marker = 0;
    std::memcpy(&marker, static_cast<const char*>(data->host_bytes) + 0x200, 8);
    Require(marker == Payload, "Mapped target lost original payload");
    for (std::size_t n = 0; n < Tags.size(); ++n) {
        std::uint64_t pointer = 0;
        std::memcpy(&pointer, static_cast<const char*>(data->host_bytes) + n * 8, 8);
        Require(pointer == ((data->address + 0x200) | (std::uint64_t(Tags[n]) << 56)),
            "Tag byte or rebased target changed in private mapping");
    }
    CheckUnchanged(path, bytes, *hash);
}
void RejectsUnmappedTargets(const fs::path& tree, std::uint16_t format) {
    const auto path = tree / "owned" / "image.dylib";
    // A high8 byte is metadata, not permission to skip containment checks.
    for (const auto target : {0x1000ull, 0x4000ull}) {
        auto bytes = Fixture(format, target); TagFirstRebase(bytes, format); Write(path, bytes);
        const auto hash = Sha256(bytes); Require(bool(hash), "Cannot hash negative fixture");
        DarwinImage metadata; std::string error;
        Require(ReadDarwinImage(path, 0x0100000c, metadata, error), "Negative chain itself is malformed: " + error);
        Require(!DarwinMappedImages::Load("/owned/image.dylib", {tree}, error, {}, DarwinMappingMode::Arm64Guest)
            && error.find("Rebase target exceeds mapped segments") != std::string::npos,
            "Tagged rebase escaped actual mapped segments: " + error);
        CheckUnchanged(path, bytes, *hash);
    }
    auto bytes = Fixture(format, Target, false); TagFirstRebase(bytes, format); Write(path, bytes);
    std::string error;
    Require(!DarwinMappedImages::Load("/owned/image.dylib", {tree}, error, {}, DarwinMappingMode::Arm64Guest)
        && error.find("Rebase target exceeds mapped segments") != std::string::npos,
        "Tagged rebase accepted a segment without access protections: " + error);
    CheckUnchanged(path, bytes, *Sha256(bytes));
}
void RejectsMalformedSlot(const fs::path& tree, std::uint16_t format) {
    auto bytes = Fixture(format);
    Put(bytes, SegmentStarts + 22, 0xffc, 2); // Eight-byte word crosses its 4KiB page.
    const auto path = tree / "owned" / "image.dylib"; Write(path, bytes);
    DarwinImage metadata; std::string error;
    Require(!ReadDarwinImage(path, 0x0100000c, metadata, error) && !metadata.chained_fixups.present
        && error.find("Chained pointer exceeds original page/segment") != std::string::npos,
        "Out-of-page source slot accepted or partial decode published: " + error);
    Require(!DarwinMappedImages::Load("/owned/image.dylib", {tree}, error, {}, DarwinMappingMode::Arm64Guest),
        "Malformed tagged source slot reached private mapper");
    CheckUnchanged(path, bytes, *Sha256(bytes));
}
}
int main() {
    try {
        TemporaryTree fixtures;
        for (const auto format : {std::uint16_t(2), std::uint16_t(6), std::uint16_t(12)}) {
            MapsTaggedTargets(fixtures.root, format);
            RejectsUnmappedTargets(fixtures.root, format);
            RejectsMalformedSlot(fixtures.root, format);
        }
        // A zippered image adds a second LC_BUILD_VERSION: macOS plus Mac
        // Catalyst loads as macOS; macOS plus iOS remains invalid.
        for (const std::uint32_t second : {6u, 2u}) {
            auto bytes = Fixture(2);
            Put(bytes, 16, 6, 4); Put(bytes, 20, 3 * 72 + 24 + 16 + 24, 4);
            Put(bytes, 288, 0x32, 4); Put(bytes, 292, 24, 4);
            Put(bytes, 296, second, 4); Put(bytes, 300, 13 << 16, 4); Put(bytes, 304, 13 << 16, 4);
            const auto path = fixtures.root / "zippered" / (std::to_string(second) + ".dylib");
            fs::create_directories(path.parent_path()); Write(path, bytes);
            DarwinImage metadata; std::string error;
            const bool read = ReadDarwinImage(path, 0x0100000c, metadata, error);
            if (second == 6) Require(read && metadata.platform == 1, "Zippered macOS/Catalyst image rejected: " + error);
            else Require(!read && error.find("Duplicate platform") != std::string::npos, "macOS/iOS platform pair admitted");
        }
        std::cout << "Standalone ARM64 chained high8 mapping/offset semantics/containment/source integrity PASS\n";
        return 0;
    } catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; return 1; }
}
