#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <array>
#include "win32_process.hpp"
namespace OpenFruit {
// Values are original bytes sealed in the corresponding negative hash slots.
// Info.plist/resources are raw files; embedded blobs include their blob header.
using CodeDirectorySpecialSlots = std::map<uint32_t, std::string>;
// Digest an already verified CodeDirectory using its declared algorithm,
// truncating to Darwin's 20-byte CDHash ABI. Does not grant process trust.
bool ComputeMachOCodeDirectoryHash(std::string_view, std::array<std::uint8_t,20>&, std::string& error);
struct MachOSigningLayout {
    uint32_t signature_offset = 0, signature_size = 0;
    uint64_t executable_offset = 0, executable_size = 0;
    bool main_executable = false;
};
// Current native contract: little-endian thin 64-bit arm64/x86_64 images with
// an existing final LC_CODE_SIGNATURE region. Never changes the image/layout.
// If supplied, XML slot 5 must be framed/parseable: execution bits are derived
// from its boolean rights; the main-binary bit is derived from the Mach-O type.
bool InspectMachOSigningLayout(std::string_view image, MachOSigningLayout& layout, std::string& error);
bool BuildMachOCodeDirectory(std::string_view image, const std::string& identifier,
    const std::string& team, const CodeDirectorySpecialSlots& special_slots,
    std::string& directory, std::string& error);
// Independent of CMS/provider success: verifies coverage and all supplied/absent
// slots. Does not establish CMS authenticity, trust, entitlement authorization,
// resource/nested-code selection or complete Mach-O semantic validity.
bool VerifyMachOCodeDirectory(std::string_view image, std::string_view directory,
    const CodeDirectorySpecialSlots& special_slots, std::string& error,
    const ProcessRunOptions& control = {});
}
