#include "macho_code_directory.hpp"
#include "entitlement_blobs.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
namespace OpenFruit {
namespace {
bool Active(std::string& error, const ProcessRunOptions* control = nullptr) {
    const auto context = CurrentOperationContext();
    if ((control && ((control->cancellation && control->cancellation->load()) ||
            std::chrono::steady_clock::now() >= control->deadline)) ||
        (context && (context->CancellationRequested() || context->DeadlineExceeded()))) {
        error = "Native CodeDirectory operation cancelled or deadline exceeded."; return false;
    }
    return true;
}
uint64_t Read(std::string_view bytes, std::size_t offset, std::size_t count, bool little = false) {
    uint64_t result = 0;
    for (std::size_t i = 0; i < count; ++i)
        result = (result << 8) | static_cast<unsigned char>(bytes[offset + (little ? count - 1 - i : i)]);
    return result;
}
bool ExecutionFlags(const CodeDirectorySpecialSlots& slots, uint64_t& flags, std::string& error) {
    flags = 0;
    const auto xml = slots.find(5);
    if (xml == slots.end()) return true;
    const std::string_view blob = xml->second;
    if (blob.size() < 8 || blob.size() > 16 * 1024 * 1024 || Read(blob, 0, 4) != 0xfade7171 || Read(blob, 4, 4) != blob.size()) {
        error = "CodeDirectory execution policy requires a complete framed XML entitlement slot."; return false;
    }
    return DeriveEntitlementExecutionFlags(blob.substr(8), flags, error);
}
void Write(std::string& bytes, std::size_t offset, uint64_t value, std::size_t count = 4) {
    for (std::size_t i = count; i; --i) { bytes[offset + i - 1] = static_cast<char>(value & 255); value >>= 8; }
}
bool Hash(std::string_view bytes, unsigned char type, std::string& digest,
    const ProcessRunOptions* control = nullptr) {
    struct State {
        BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
        ~State() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    } state;
    const auto algorithm = type == 1 ? BCRYPT_SHA1_ALGORITHM : type == 4 ? BCRYPT_SHA384_ALGORITHM : BCRYPT_SHA256_ALGORITHM;
    digest.resize(type == 1 ? 20 : type == 4 ? 48 : 32);
    if (BCryptOpenAlgorithmProvider(&state.algorithm, algorithm, nullptr, 0) < 0 ||
        BCryptCreateHash(state.algorithm, &state.hash, nullptr, 0, nullptr, 0, 0) < 0) return false;
    for (std::size_t offset = 0; offset < bytes.size();) {
        std::string ignored;
        if (!Active(ignored, control)) return false;
        const auto count = static_cast<ULONG>(std::min<std::size_t>(bytes.size() - offset, 1024 * 1024));
        if (BCryptHashData(state.hash, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data() + offset)), count, 0) < 0) return false;
        offset += count;
    }
    if (BCryptFinishHash(state.hash, reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), 0) < 0) return false;
    if (type == 3) digest.resize(20);
    return true;
}
bool CheckSlots(const CodeDirectorySpecialSlots& slots, std::string& error) {
    std::size_t total = 0;
    for (const auto& [slot, value] : slots) {
        // Slots >= 0x1000 are SuperBlob indexes, never negative CD hashes.
        if (!slot || slot >= 0x1000 || value.empty() || value.size() > 16 * 1024 * 1024 - total) {
            error = "CodeDirectory special-slot inputs are invalid or exceed the input limit."; return false;
        }
        total += value.size();
    }
    return true;
}
}
bool ComputeMachOCodeDirectoryHash(std::string_view directory, std::array<std::uint8_t,20>& output, std::string& error) {
    output={};error.clear();
    if(directory.size()<44||Read(directory,0,4)!=0xfade0c02||Read(directory,4,4)!=directory.size()){
        error="CodeDirectory digest input is malformed.";return false;
    }
    const auto type=static_cast<unsigned char>(directory[37]);std::string digest;
    if(type<1||type>4||!Hash(directory,type,digest)||digest.size()<output.size()){
        error="CodeDirectory digest provider failed or algorithm is unsupported.";return false;
    }
    std::copy_n(reinterpret_cast<const std::uint8_t*>(digest.data()),output.size(),output.begin());return true;
}
bool InspectMachOSigningLayout(std::string_view image, MachOSigningLayout& layout, std::string& error) {
    layout = {}; error.clear();
    if (!Active(error)) return false;
    auto Fail = [&](const char* message) { error = message; return false; };
    if (image.size() < 32 || image.size() > UINT32_MAX || Read(image, 0, 4, true) != 0xfeedfacf)
        return Fail("Native signing requires a bounded little-endian thin 64-bit Mach-O image.");
    const auto cpu = Read(image, 4, 4, true), file_type = Read(image, 12, 4, true);
    if ((cpu != 0x0100000c && cpu != 0x01000007) || (file_type != 2 && file_type != 6 && file_type != 8))
        return Fail("Mach-O architecture/file type is unsupported by native signing.");
    const auto commands = Read(image, 16, 4, true), commands_size = Read(image, 20, 4, true);
    if (commands_size > image.size() - 32 || commands_size > 16 * 1024 * 1024 || commands > 65536 || commands > commands_size / 8)
        return Fail("Mach-O load-command table is outside the image.");
    const std::size_t table_end = 32 + static_cast<std::size_t>(commands_size);
    std::size_t offset = 32;
    bool signature = false, executable = false, linkedit = false;
    uint64_t linkedit_offset = 0, linkedit_size = 0, other_segment_end = 0;
    MachOSigningLayout result;
    result.main_executable = file_type == 2;
    for (uint64_t i = 0; i < commands; ++i) {
        if (!Active(error)) return false;
        if (offset > table_end || table_end - offset < 8) return Fail("Mach-O load-command header is truncated.");
        const auto command = Read(image, offset, 4, true), size = Read(image, offset + 4, 4, true);
        if (size < 8 || size % 8 || size > table_end - offset) return Fail("Mach-O load-command size is invalid.");
        if (command == 0x1d) {
            if (signature || size != 16) return Fail("Mach-O signature command is duplicate or malformed.");
            result.signature_offset = static_cast<uint32_t>(Read(image, offset + 8, 4, true));
            result.signature_size = static_cast<uint32_t>(Read(image, offset + 12, 4, true));
            signature = true;
        }
        if (command == 0x19) {
            if (size < 72 || (size - 72) % 80 || Read(image, offset + 64, 4, true) != (size - 72) / 80)
                return Fail("Mach-O segment/section table is malformed.");
            const auto file_offset = Read(image, offset + 40, 8, true), file_size = Read(image, offset + 48, 8, true);
            if (file_offset > image.size() || file_size > image.size() - file_offset)
                return Fail("Mach-O segment is outside the image.");
            if (image.substr(offset + 8, 16) == std::string_view("__LINKEDIT\0\0\0\0\0\0", 16)) {
                if (linkedit) return Fail("Mach-O has duplicate LINKEDIT segments.");
                linkedit = true; linkedit_offset = file_offset; linkedit_size = file_size;
            } else if (file_size) other_segment_end = std::max(other_segment_end, file_offset + file_size);
            if ((Read(image, offset + 60, 4, true) & 4) && file_size) {
                if (executable) return Fail("Multiple executable Mach-O segments require an additional signing contract.");
                executable = true; result.executable_offset = file_offset; result.executable_size = file_size;
            }
        }
        if (command == 0x21) return Fail("32-bit Mach-O encryption commands are unsupported in the native 64-bit signing contract.");
        if (command == 0x2c) {
            if (size != 24 || Read(image, offset + 16, 4, true))
                return Fail("Encrypted or malformed encryption-info Mach-O images require an additional signing contract.");
        }
        offset += static_cast<std::size_t>(size);
    }
    if (offset != table_end || !signature || !executable || !linkedit || !result.signature_size ||
        result.signature_offset < table_end || result.signature_offset > image.size() ||
        result.signature_size != image.size() - result.signature_offset ||
        linkedit_offset > result.signature_offset || linkedit_size != image.size() - linkedit_offset || other_segment_end > result.signature_offset ||
        result.executable_offset > result.signature_offset || result.executable_size > result.signature_offset - result.executable_offset)
        return Fail("Mach-O signing region is missing, nonfinal or overlaps executable/header bytes.");
    layout = result; return true;
}
bool BuildMachOCodeDirectory(std::string_view image, const std::string& identifier,
    const std::string& team, const CodeDirectorySpecialSlots& special_slots, std::string& directory, std::string& error) {
    bool completed = false;
    OperationSpan phase("signing.code-directory-build", JsonValue::ObjectValue(), [&] { return completed; });
    directory.clear(); error.clear();
    MachOSigningLayout layout;
    if (!InspectMachOSigningLayout(image, layout, error) || !CheckSlots(special_slots, error)) return false;
    uint64_t execution_flags = 0;
    if (!ExecutionFlags(special_slots, execution_flags, error)) return false;
    if (identifier.empty() || identifier.size() > 1024 || identifier.find('\0') != std::string::npos ||
        team.size() != 10 || team.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos) {
        error = "CodeDirectory requires a bounded identifier and a valid team."; return false;
    }
    // Generic iOS signing policy: SHA-256, 4KiB pages, through-exec-segment header.
    const uint32_t pages = (layout.signature_offset - 1) / 4096 + 1;
    const uint32_t specials = special_slots.empty() ? 0 : special_slots.rbegin()->first;
    if (uint64_t(88) + identifier.size() + 1 + team.size() + 1 + uint64_t(pages + specials) * 32 > 16 * 1024 * 1024) {
        error = "Generated CodeDirectory exceeds its input limit."; return false;
    }
    std::string result(88, '\0');
    Write(result, 0, 0xfade0c02); Write(result, 8, 0x20400);
    Write(result, 20, result.size()); result += identifier; result += '\0';
    Write(result, 48, result.size()); result += team; result += '\0';
    result.append(static_cast<std::size_t>(specials) * 32, '\0');
    const auto hash_offset = result.size();
    Write(result, 16, hash_offset); Write(result, 24, specials); Write(result, 28, pages);
    Write(result, 32, layout.signature_offset); result[36] = 32; result[37] = 2; result[39] = 12;
    Write(result, 64, layout.executable_offset, 8); Write(result, 72, layout.executable_size, 8);
    Write(result, 80, execution_flags | (layout.main_executable ? 1 : 0), 8);
    std::string digest;
    for (const auto& [slot, value] : special_slots) {
        if (!Hash(value, 2, digest)) { error = "Unable to hash CodeDirectory special slot."; return false; }
        result.replace(hash_offset - static_cast<std::size_t>(slot) * 32, 32, digest);
    }
    for (uint64_t offset = 0; offset < layout.signature_offset; offset += 4096) {
        const auto size = std::min<uint64_t>(4096, layout.signature_offset - offset);
        if (!Hash(image.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(size)), 2, digest)) {
            error = "Unable to hash Mach-O code page."; return false;
        }
        result += digest;
    }
    Write(result, 4, result.size()); directory = std::move(result); completed = true; return true;
}
bool VerifyMachOCodeDirectory(std::string_view image, std::string_view directory,
    const CodeDirectorySpecialSlots& special_slots, std::string& error,
    const ProcessRunOptions& control) {
    bool verified = false;
    OperationSpan phase("signing.code-directory-verify", JsonValue::ObjectValue(), [&] { return verified; });
    const auto progress_context = phase.Context();
    error.clear();
    auto Fail = [&](const char* message) { error = message; return false; };
    MachOSigningLayout layout;
    if (!Active(error, &control) || !InspectMachOSigningLayout(image, layout, error) || !CheckSlots(special_slots, error)) return false;
    if (directory.size() < 44 || directory.size() > 16 * 1024 * 1024 || Read(directory, 0, 4) != 0xfade0c02 || Read(directory, 4, 4) != directory.size())
        return Fail("CodeDirectory magic/length is invalid.");
    const auto version = Read(directory, 8, 4);
    if (version < 0x20001 || version > 0x20500) return Fail("CodeDirectory version is unsupported by the page verifier.");
    const std::size_t header = version >= 0x20500 ? 96 : version >= 0x20400 ? 88 : version >= 0x20300 ? 64 : version >= 0x20200 ? 52 : version >= 0x20100 ? 48 : 44;
    if (directory.size() < header || Read(directory, 40, 4) || (version >= 0x20100 && Read(directory, 44, 4)) ||
        (version >= 0x20300 && Read(directory, 52, 4)) || (version >= 0x20500 && Read(directory, 92, 4)))
        return Fail("CodeDirectory header is malformed or uses unsupported scatter/pre-encryption tables.");
    const auto type = static_cast<unsigned char>(directory[37]), hash_size = static_cast<unsigned char>(directory[36]);
    if (type < 1 || type > 4 || hash_size != (type == 1 || type == 3 ? 20 : type == 4 ? 48 : 32)) return Fail("CodeDirectory hash algorithm/size is invalid.");
    const auto hash_offset = Read(directory, 16, 4), specials = Read(directory, 24, 4), pages = Read(directory, 28, 4);
    uint64_t limit = Read(directory, 32, 4);
    if (version >= 0x20300 && Read(directory, 56, 8)) limit = Read(directory, 56, 8);
    const auto shift = static_cast<unsigned char>(directory[39]);
    if (shift > 31 || limit != layout.signature_offset) return Fail("CodeDirectory does not cover the complete unsigned Mach-O region.");
    const uint64_t page_size = shift ? uint64_t(1) << shift : limit;
    if (!page_size || pages != (limit - 1) / page_size + 1 || hash_offset < header ||
        specials > (hash_offset - header) / hash_size || hash_offset > directory.size() || pages > (directory.size() - hash_offset) / hash_size)
        return Fail("CodeDirectory page/special hash table is invalid.");
    const auto metadata_end = hash_offset - specials * hash_size;
    auto StringInside = [&](uint64_t position) {
        if (position < header || position >= metadata_end) return false;
        const auto end = directory.find('\0', static_cast<std::size_t>(position));
        return end != std::string_view::npos && end > position && end < metadata_end;
    };
    if (!StringInside(Read(directory, 20, 4)) || (version >= 0x20200 && Read(directory, 48, 4) && !StringInside(Read(directory, 48, 4))))
        return Fail("CodeDirectory strings are outside metadata.");
    if (version >= 0x20400) {
        uint64_t execution_flags = 0;
        if (!ExecutionFlags(special_slots, execution_flags, error)) return false;
        if (Read(directory, 64, 8) != layout.executable_offset || Read(directory, 72, 8) != layout.executable_size ||
            Read(directory, 80, 8) != (execution_flags | (layout.main_executable ? 1 : 0)))
            return Fail("CodeDirectory executable-segment metadata/flags disagree with Mach-O and sealed entitlements.");
    }
    if (!special_slots.empty() && special_slots.rbegin()->first > specials) return Fail("CodeDirectory omitted a supplied special slot.");
    std::string digest;
    for (uint64_t slot = 1; slot <= specials; ++slot) {
        const auto found = special_slots.find(static_cast<uint32_t>(slot));
        if (found == special_slots.end()) digest.assign(hash_size, '\0');
        else if (!Hash(found->second, type, digest, &control)) return Fail("Unable to verify CodeDirectory special hash.");
        if (directory.substr(static_cast<std::size_t>(hash_offset - slot * hash_size), hash_size) != digest)
            return Fail("CodeDirectory special slot is missing, unexpected or altered.");
    }
    for (uint64_t page = 0; page < pages; ++page) {
        const auto offset = page * page_size, size = std::min(page_size, limit - offset);
        if (!Hash(image.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(size)), type, digest, &control)) return Fail("Unable to verify Mach-O page hash.");
        if (directory.substr(static_cast<std::size_t>(hash_offset + page * hash_size), hash_size) != digest) return Fail("Mach-O code page hash mismatch.");
        const auto completed_pages = page + 1;
        // Actual completed work, bounded to logarithmically many events even
        // for large images; no test hook or estimated completion percentage.
        if (progress_context && ((completed_pages & (completed_pages - 1)) == 0 || completed_pages == pages)) {
            auto progress = JsonValue::ObjectValue();
            progress.Set("pages_verified", JsonValue::Number(std::to_string(completed_pages)));
            progress.Set("pages_total", JsonValue::Number(std::to_string(pages)));
            progress_context->Emit("signing.code-directory.verify-progress", std::move(progress));
        }
        if (!Active(error, &control)) return false;
    }
    verified = true; return true;
}
}
