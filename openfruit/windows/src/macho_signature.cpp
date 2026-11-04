#include "macho_signature.hpp"
#include "entitlement_blobs.hpp"
#include "code_directory_cms.hpp"
#include "provisioning_identity.hpp"
#include "signing_credential.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <plist/plist.h>
#include <vector>
#include <set>
#include <algorithm>
namespace OpenFruit {
namespace {
constexpr std::size_t maximum_signature = 16 * 1024 * 1024;
uint64_t Read(std::string_view bytes, std::size_t offset, std::size_t count = 4, bool little = false) {
    uint64_t value = 0;
    for (std::size_t i = 0; i < count; ++i)
        value = (value << 8) | static_cast<unsigned char>(bytes[offset + (little ? count - i - 1 : i)]);
    return value;
}
void Write(std::string& bytes, std::size_t offset, uint64_t value, std::size_t count = 4, bool little = false) {
    for (std::size_t i = 0; i < count; ++i) { bytes[offset + (little ? i : count - i - 1)] = static_cast<char>(value & 255); value >>= 8; }
}
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
    bool Parse(std::string_view bytes) { return bytes.size() <= maximum_signature &&
        plist_from_memory(bytes.data(), static_cast<uint32_t>(bytes.size()), &value, nullptr) == PLIST_ERR_SUCCESS && plist_get_node_type(value) == PLIST_DICT; }
};
bool Framed(uint32_t slot, std::string_view blob) {
    const auto magic = slot == 2 ? 0xfade0c01u : slot == 5 ? 0xfade7171u : slot == 7 ? 0xfade7172u : 0u;
    return magic && blob.size() >= 8 && blob.size() <= maximum_signature && Read(blob, 0) == magic && Read(blob, 4) == blob.size();
}
bool Inputs(const CodeDirectorySpecialSlots& external, const CodeDirectorySpecialSlots& embedded, std::string& error) {
    std::size_t size = 0;
    for (const auto& [slot, bytes] : external) {
        if ((slot != 1 && slot != 3) || bytes.empty() || bytes.size() > maximum_signature - size) {
            error = "Native Mach-O signature requires bounded original external slots 1/3."; return false;
        }
        size += bytes.size();
    }
    for (const auto& [slot, bytes] : embedded) {
        if (!Framed(slot, bytes) || bytes.size() > maximum_signature - size) {
            error = "Native Mach-O embedded slot is unsupported, malformed or exceeds the input limit."; return false;
        }
        size += bytes.size();
    }
    return true;
}
bool EntitlementInputs(const PreparedEntitlementRequest& binding,
    const CodeDirectorySpecialSlots& embedded, std::string& error) {
    return ValidateProvisioningEntitlementBlobs(binding, embedded, error);
}
std::string SuperBlob(const CodeDirectorySpecialSlots& blobs) {
    std::string result(12 + blobs.size() * 8, '\0');
    Write(result, 0, 0xfade0cc0); Write(result, 8, blobs.size());
    std::size_t index = 12;
    for (const auto& [slot, bytes] : blobs) {
        if (bytes.size() > maximum_signature - result.size()) return {};
        Write(result, index, slot); Write(result, index + 4, result.size());
        result += bytes; index += 8;
    }
    Write(result, 4, result.size()); return result;
}
bool ResizeLayout(std::string_view original, std::size_t capacity, std::string& image, std::string& error) {
    MachOSigningLayout layout;
    if (!InspectMachOSigningLayout(original, layout, error)) return false;
    const uint64_t final_size = uint64_t(layout.signature_offset) + capacity;
    if (!capacity || capacity > maximum_signature || final_size > UINT32_MAX) { error = "Native signature allocation exceeds supported image limits."; return false; }
    image.assign(original.substr(0, layout.signature_offset)); image.resize(static_cast<std::size_t>(final_size), '\0');
    const auto commands = Read(original, 16, 4, true);
    std::size_t position = 32;
    std::vector<std::pair<uint64_t, uint64_t>> vm_ranges;
    for (uint64_t i = 0; i < commands; ++i) {
        const auto command = Read(original, position, 4, true), size = Read(original, position + 4, 4, true);
        if (command == 0x1d) Write(image, position + 12, capacity, 4, true);
        uint64_t vm_size = command == 0x19 ? Read(original, position + 32, 8, true) : 0;
        if (command == 0x19 && original.substr(position + 8, 16) == std::string_view("__LINKEDIT\0\0\0\0\0\0", 16)) {
            const auto file_offset = Read(original, position + 40, 8, true);
            const auto new_file_size = final_size - file_offset;
            // Preserve linker VM allocation when sufficient. Larger allocation
            // uses the native Mach-O VM granule for this architecture.
            const uint64_t granule = Read(original, 4, 4, true) == 0x0100000c ? 16384 : 4096;
            const auto new_vm_size = (new_file_size + granule - 1) / granule * granule;
            vm_size = std::max(vm_size, new_vm_size);
            Write(image, position + 32, vm_size, 8, true);
            Write(image, position + 48, new_file_size, 8, true);
        }
        if (command == 0x19 && vm_size) {
            const auto vm_address = Read(original, position + 24, 8, true);
            if (vm_size > UINT64_MAX - vm_address) { error = "Native signature resize overflows Mach-O VM range."; return false; }
            vm_ranges.emplace_back(vm_address, vm_address + vm_size);
        }
        position += static_cast<std::size_t>(size);
    }
    std::sort(vm_ranges.begin(), vm_ranges.end());
    for (std::size_t i = 1; i < vm_ranges.size(); ++i)
        if (vm_ranges[i].first < vm_ranges[i - 1].second) { error = "Native signature resize overlaps Mach-O VM segments."; return false; }
    return true;
}
struct Decoded {
    std::vector<BYTE> bytes;
    bool Decode(LPCSTR kind, const CRYPT_DATA_BLOB& blob) {
        DWORD size = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, kind, blob.pbData, blob.cbData, 0, nullptr, nullptr, &size) || size > maximum_signature) return false;
        bytes.resize(size);
        return CryptDecodeObjectEx(X509_ASN_ENCODING, kind, blob.pbData, blob.cbData, 0, nullptr, bytes.data(), &size) != FALSE;
    }
};
bool VerifyCms(std::string_view cms, std::string_view directory, const SigningCredential& credential) {
    CRYPT_VERIFY_MESSAGE_PARA verify{};
    verify.cbSize = sizeof(verify); verify.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE* content = reinterpret_cast<const BYTE*>(directory.data()); DWORD content_size = static_cast<DWORD>(directory.size());
    struct Cert { PCCERT_CONTEXT value = nullptr; ~Cert() { if (value) CertFreeCertificateContext(value); } } signer;
    if (!CryptVerifyDetachedMessageSignature(&verify, 0, reinterpret_cast<const BYTE*>(cms.data()), static_cast<DWORD>(cms.size()), 1, &content, &content_size, &signer.value) ||
        !signer.value || std::string_view(reinterpret_cast<const char*>(signer.value->pbCertEncoded), signer.value->cbCertEncoded) != credential.CertificateDer()) return false;
    struct Message {
        HCRYPTMSG value = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, nullptr, nullptr);
        ~Message() { if (value) CryptMsgClose(value); }
    } message;
    if (!message.value || !CryptMsgUpdate(message.value, reinterpret_cast<const BYTE*>(cms.data()), static_cast<DWORD>(cms.size()), TRUE)) return false;
    DWORD size = 0;
    if (!CryptMsgGetParam(message.value, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, nullptr, &size) || size > maximum_signature) return false;
    std::vector<BYTE> bytes(size);
    if (!CryptMsgGetParam(message.value, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, bytes.data(), &size)) return false;
    const auto attrs = reinterpret_cast<const CRYPT_ATTRIBUTES*>(bytes.data());
    const CRYPT_ATTRIBUTE *v1 = nullptr, *v2 = nullptr;
    std::set<std::string> oids;
    for (DWORD i = 0; i < attrs->cAttr; ++i) {
        const auto& attr = attrs->rgAttr[i];
        if (!oids.insert(attr.pszObjId).second) return false;
        if (std::string_view(attr.pszObjId) == "1.2.840.113635.100.9.1") v1 = &attr;
        if (std::string_view(attr.pszObjId) == "1.2.840.113635.100.9.2") v2 = &attr;
    }
    if (!v1 || !v2 || v1->cValue != 1 || v2->cValue != 1) return false;
    BYTE digest[32]; DWORD digest_size = sizeof(digest);
    if (!CryptHashCertificate2(L"SHA256", 0, nullptr, content, content_size, digest, &digest_size) || digest_size != 32) return false;
    Decoded octet;
    if (!octet.Decode(X509_OCTET_STRING, v1->rgValue[0])) return false;
    const auto blob = reinterpret_cast<const CRYPT_DATA_BLOB*>(octet.bytes.data());
    Plist hashes;
    if (!hashes.Parse({reinterpret_cast<const char*>(blob->pbData), blob->cbData})) return false;
    const auto array = plist_dict_get_item(hashes.value, "cdhashes");
    if (!array || plist_get_node_type(array) != PLIST_ARRAY || plist_array_get_size(array) != 1) return false;
    const auto item = plist_array_get_item(array, 0);
    uint64_t count = 0; const auto hash_bytes = plist_get_node_type(item) == PLIST_DATA ? plist_get_data_ptr(item, &count) : nullptr;
    if (!hash_bytes || count != 20 || std::string_view(hash_bytes, 20) != std::string_view(reinterpret_cast<const char*>(digest), 20)) return false;
    Decoded sequence;
    if (!sequence.Decode(X509_SEQUENCE_OF_ANY, v2->rgValue[0])) return false;
    const auto values = reinterpret_cast<const CRYPT_SEQUENCE_OF_ANY*>(sequence.bytes.data());
    if (values->cValue != 2) return false;
    Decoded oid, hash;
    if (!oid.Decode(X509_OBJECT_IDENTIFIER, values->rgValue[0]) || !hash.Decode(X509_OCTET_STRING, values->rgValue[1])) return false;
    const auto hash_blob = reinterpret_cast<const CRYPT_DATA_BLOB*>(hash.bytes.data());
    return std::string_view(*reinterpret_cast<char* const*>(oid.bytes.data())) == szOID_NIST_sha256 && hash_blob->cbData == 32 &&
        std::string_view(reinterpret_cast<const char*>(hash_blob->pbData), 32) == std::string_view(reinterpret_cast<const char*>(digest), 32);
}
}
bool VerifyProvisionedThinMachO(std::string_view image, const PreparedEntitlementRequest& binding,
    const SigningCredential& credential, const CodeDirectorySpecialSlots& external_slots,
    const CodeDirectorySpecialSlots& expected_embedded_blobs, std::string& error) {
    bool verified = false;
    OperationSpan phase("signing.macho-verify", JsonValue::ObjectValue(), [&] { return verified; });
    error.clear();
    auto Fail = [&](const char* reason) { error = reason; return false; };
    MachOSigningLayout layout;
    if (!InspectMachOSigningLayout(image, layout, error) || !Inputs(external_slots, expected_embedded_blobs, error) ||
        !EntitlementInputs(binding, expected_embedded_blobs, error)) return false;
    const auto signature = image.substr(layout.signature_offset, layout.signature_size);
    if (signature.size() < 12 || signature.size() > maximum_signature || Read(signature, 0) != 0xfade0cc0) return Fail("Mach-O embedded signature is invalid.");
    const auto length = Read(signature, 4), count = Read(signature, 8);
    if (length > signature.size() || length < 12 || count > 5 || count < 2 || count > (length - 12) / 8 ||
        signature.substr(static_cast<std::size_t>(length)).find_first_not_of('\0') != std::string_view::npos)
        return Fail("Mach-O signature table/length/padding is invalid.");
    std::map<uint32_t, std::string_view> blobs;
    uint64_t cursor = 12 + count * 8;
    for (uint64_t index = 0; index < count; ++index) {
        const auto slot = static_cast<uint32_t>(Read(signature, 12 + index * 8));
        const auto offset = Read(signature, 16 + index * 8);
        if (offset != cursor || cursor > length || length - cursor < 8 || (!blobs.empty() && slot <= blobs.rbegin()->first)) return Fail("Mach-O signature blobs are overlapping, unordered or duplicated.");
        const auto blob_size = Read(signature, static_cast<std::size_t>(offset) + 4);
        if (blob_size < 8 || blob_size > length - cursor) return Fail("Mach-O signature blob exceeds its container.");
        blobs.emplace(slot, signature.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(blob_size))); cursor += blob_size;
    }
    if (cursor != length || !blobs.contains(0) || !blobs.contains(0x10000)) return Fail("Mach-O signature has missing or unindexed blobs.");
    CodeDirectorySpecialSlots slots = external_slots;
    for (const auto& [slot, blob] : blobs) {
        if (slot == 0 || slot == 0x10000) continue;
        const auto found = expected_embedded_blobs.find(slot);
        if (!Framed(slot, blob) || found == expected_embedded_blobs.end() || found->second != blob) return Fail("Mach-O embedded special blob differs from its expected stage input.");
        slots.emplace(slot, blob);
    }
    if (blobs.size() != expected_embedded_blobs.size() + 2) return Fail("Mach-O signature omitted an embedded input.");
    const auto directory = blobs.at(0), wrapper = blobs.at(0x10000);
    if (!VerifyMachOCodeDirectory(image, directory, slots, error)) return false;
    if (directory.size() < 88 || Read(directory, 8) != 0x20400 || Read(directory, 12) || directory[37] != 2 || directory[38])
        return Fail("Mach-O certificate-backed CodeDirectory policy is invalid.");
    const auto identifier_offset = static_cast<std::size_t>(Read(directory, 20)), team_offset = static_cast<std::size_t>(Read(directory, 48));
    if (!team_offset || team_offset >= directory.size() || directory.find('\0', team_offset) == std::string_view::npos) return Fail("Mach-O CodeDirectory team is missing.");
    const auto identifier = directory.substr(identifier_offset, directory.find('\0', identifier_offset) - identifier_offset);
    const auto team = directory.substr(team_offset, directory.find('\0', team_offset) - team_offset);
    if (identifier != binding.bundle_identifier || !ValidateProvisioningSigningCertificate(binding, credential, error, std::string(team))) return error.empty() ? Fail("Mach-O CodeDirectory bundle identity differs from its checked profile binding.") : false;
    if (Read(wrapper, 0) != 0xfade0b01 || !VerifyCms(wrapper.substr(8), directory, credential)) return Fail("Mach-O detached CMS/certificate/hash-agility verification failed.");
    verified = true; return true;
}
bool SignProvisionedThinMachO(std::string_view image, const PreparedEntitlementRequest& binding,
    const SigningCredential& credential, const CodeDirectorySpecialSlots& external_slots,
    const CodeDirectorySpecialSlots& embedded_blobs, std::string& signed_image, std::string& error) {
    bool completed = false;
    OperationSpan phase("signing.macho-sign", JsonValue::ObjectValue(), [&] { return completed; });
    // Support an explicitly requested in-place buffer transformation without
    // invalidating the input view when clearing the result.
    std::string aliased_input;
    const auto input_address = reinterpret_cast<uintptr_t>(image.data());
    const auto output_address = reinterpret_cast<uintptr_t>(signed_image.data());
    if (!image.empty() && !signed_image.empty() && input_address < output_address + signed_image.size() &&
        output_address < input_address + image.size()) { aliased_input.assign(image); image = aliased_input; }
    signed_image.clear(); error.clear();
    if (!Inputs(external_slots, embedded_blobs, error) || !EntitlementInputs(binding, embedded_blobs, error)) return false;
    Plist entitlements;
    if (!entitlements.Parse(binding.profile_signature_entitlements_xml)) { error = "Native Mach-O signing requires prepared signature inputs."; return false; }
    const auto team_node = plist_dict_get_item(entitlements.value, "com.apple.developer.team-identifier");
    uint64_t team_size = 0; const auto team_bytes = team_node && plist_get_node_type(team_node) == PLIST_STRING ? plist_get_string_ptr(team_node, &team_size) : nullptr;
    if (!team_bytes || team_size != 10) { error = "Prepared signature team is invalid."; return false; }
    const std::string team(team_bytes, static_cast<std::size_t>(team_size));
    CodeDirectorySpecialSlots slots = external_slots;
    slots.insert(embedded_blobs.begin(), embedded_blobs.end());
    // Actual signing always hashes the resized header. Allocation slack
    // absorbs variable-length asymmetric signatures;
    // bounded retries only grow allocation and never publish partial output.
    std::size_t capacity = 4096;
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::string result, directory, cms;
        if (!ResizeLayout(image, capacity, result, error) || !BuildMachOCodeDirectory(result, binding.bundle_identifier, team, slots, directory, error) ||
            !BuildProvisioningCodeDirectoryCms(binding, credential, {directory}, cms, error)) return false;
        std::string wrapper(8, '\0'); Write(wrapper, 0, 0xfade0b01); wrapper += cms; Write(wrapper, 4, wrapper.size());
        CodeDirectorySpecialSlots blobs = embedded_blobs; blobs.emplace(0, std::move(directory)); blobs.emplace(0x10000, std::move(wrapper));
        const auto signature = SuperBlob(blobs);
        if (signature.empty()) { error = "Mach-O SuperBlob exceeds its signature limit."; return false; }
        if (signature.size() > capacity) { capacity = (signature.size() + 4095) / 4096 * 4096; continue; }
        MachOSigningLayout layout;
        if (!InspectMachOSigningLayout(result, layout, error)) return false;
        result.replace(layout.signature_offset, signature.size(), signature);
        if (!VerifyProvisionedThinMachO(result, binding, credential, external_slots, embedded_blobs, error)) return false;
        signed_image = std::move(result); completed = true; return true;
    }
    error = "Mach-O signature allocation did not converge within the bounded signing attempts."; return false;
}
}
