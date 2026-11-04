#include "code_directory_cms.hpp"
#include "provisioning_identity.hpp"
#include "signing_credential.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <plist/plist.h>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string_view>
namespace OpenFruit {
namespace {
uint32_t Word(std::string_view bytes, std::size_t offset) {
    uint32_t result = 0;
    for (std::size_t i = 0; i < 4; ++i)
        result = (result << 8) | static_cast<unsigned char>(bytes[offset + i]);
    return result;
}
struct Directory {
    std::string identifier, team;
    const wchar_t* algorithm = nullptr;
    const char* oid = nullptr;
    std::size_t digest_size = 0;
};
bool Parse(std::string_view bytes, Directory& output, std::string& error) {
    auto Fail = [&](const char* message) { error = message; return false; };
    if (bytes.size() < 52 || bytes.size() > 16 * 1024 * 1024 || Word(bytes, 0) != 0xfade0c02 ||
        Word(bytes, 4) != bytes.size()) return Fail("CodeDirectory magic or bounded length is invalid.");
    const auto version = Word(bytes, 8);
    // This parser owns the published through-0x20500 header contract. Do not
    // guess layouts of future versions or silently ignore scatter tables.
    if (version < 0x20200 || version > 0x20500)
        return Fail("CodeDirectory version is unsupported by the native CMS provider.");
    const std::size_t header = version >= 0x20500 ? 96 : version >= 0x20400 ? 88 : version >= 0x20300 ? 64 : 52;
    if (bytes.size() < header || Word(bytes, 40) || Word(bytes, 44) ||
        (Word(bytes, 12) & 2) || bytes[38] != 0)
        return Fail("CodeDirectory header is truncated, scattered, ad-hoc or platform-reserved.");
    const auto type = static_cast<unsigned char>(bytes[37]);
    const auto hash_size = static_cast<unsigned char>(bytes[36]);
    switch (type) {
    case 1: output.algorithm = BCRYPT_SHA1_ALGORITHM; output.oid = szOID_OIWSEC_sha1; output.digest_size = 20; break;
    case 2: case 3: output.algorithm = BCRYPT_SHA256_ALGORITHM; output.oid = szOID_NIST_sha256; output.digest_size = 32; break;
    case 4: output.algorithm = BCRYPT_SHA384_ALGORITHM; output.oid = szOID_NIST_sha384; output.digest_size = 48; break;
    default: return Fail("CodeDirectory hash algorithm is unsupported.");
    }
    if (hash_size != (type == 3 ? 20 : output.digest_size)) return Fail("CodeDirectory hash size disagrees with its algorithm.");
    const uint64_t hashes = Word(bytes, 16), special = uint64_t(Word(bytes, 24)) * hash_size;
    const uint64_t code_hashes = uint64_t(Word(bytes, 28)) * hash_size;
    if (hashes < header || special > hashes - header || hashes > bytes.size() || code_hashes > bytes.size() - hashes)
        return Fail("CodeDirectory hash slots are outside the blob.");
    const auto metadata_end = static_cast<std::size_t>(hashes - special);
    const auto identifier_offset = Word(bytes, 20), team_offset = Word(bytes, 48);
    auto ReadString = [&](std::size_t offset, std::string& result) {
        if (offset < header || offset >= metadata_end) return false;
        const auto end = bytes.find('\0', offset);
        if (end == std::string_view::npos || end >= metadata_end || end == offset || end - offset > 1024) return false;
        result.assign(bytes.substr(offset, end - offset)); return true;
    };
    if (!ReadString(identifier_offset, output.identifier) || !ReadString(team_offset, output.team) ||
        !(identifier_offset + output.identifier.size() < team_offset || team_offset + output.team.size() < identifier_offset))
        return Fail("CodeDirectory identifier/team strings are missing, overlapping or outside metadata.");
    if (output.team.size() != 10) return Fail("CodeDirectory team identifier is invalid.");
    for (const unsigned char ch : output.team)
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) return Fail("CodeDirectory team identifier is invalid.");
    if (version >= 0x20300 && Word(bytes, 52)) return Fail("CodeDirectory reserved header field is nonzero.");
    if (version >= 0x20500 && Word(bytes, 92))
        return Fail("Pre-encryption CodeDirectories require an additional native provider contract.");
    // Slot/page content belongs to the Mach-O verifier, not this CMS encoder.
    return true;
}
std::string Tlv(unsigned char tag, std::string_view value) {
    std::string result(1, static_cast<char>(tag));
    if (value.size() < 128) result += static_cast<char>(value.size());
    else {
        std::string length;
        for (auto size = value.size(); size; size >>= 8) length.insert(length.begin(), static_cast<char>(size & 255));
        result += static_cast<char>(128 | length.size()); result += length;
    }
    result.append(value); return result;
}
bool Oid(const char* oid, std::string& result) {
    DWORD size = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, &oid, 0, nullptr, nullptr, &size)) return false;
    result.resize(size);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, &oid, 0, nullptr, result.data(), &size)) return false;
    result.resize(size); return true;
}
bool Digest(std::string_view bytes, const Directory& directory, std::string& digest) {
    struct NativeHash {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        ~NativeHash() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    } native;
    digest.resize(directory.digest_size);
    return BCryptOpenAlgorithmProvider(&native.algorithm, directory.algorithm, nullptr, 0) >= 0 &&
        BCryptCreateHash(native.algorithm, &native.hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
        BCryptHashData(native.hash, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) >= 0 &&
        BCryptFinishHash(native.hash, reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), 0) >= 0;
}
}
bool BuildProvisioningCodeDirectoryCms(const PreparedEntitlementRequest& bundle,
    const SigningCredential& credential, const std::vector<std::string>& directories,
    std::string& cms, std::string& error) {
    bool completed = false;
    OperationSpan phase("signing.code-directory-cms", JsonValue::ObjectValue(), [&] { return completed; });
    cms.clear(); error.clear();
    if (directories.empty() || directories.size() > 6) { error = "CMS requires a primary CodeDirectory and at most five alternates."; return false; }
    struct Plist { plist_t value = plist_new_dict(); ~Plist() { if (value) plist_free(value); } } hashes;
    const auto array = plist_new_array();
    plist_dict_set_item(hashes.value, "cdhashes", array);
    CmsAuthenticatedAttribute v2{"1.2.840.113635.100.9.2", {}};
    std::set<std::string> algorithms;
    std::string team;
    std::size_t total = 0;
    for (const auto& bytes : directories) {
        if (bytes.size() > 16 * 1024 * 1024 - total) { error = "CodeDirectory collection exceeds its input limit."; return false; }
        total += bytes.size();
        Directory directory;
        if (!Parse(bytes, directory, error)) return false;
        if (directory.identifier != bundle.bundle_identifier || (!team.empty() && team != directory.team)) {
            error = "CodeDirectory bundle/team identity disagrees with its checked bundle or alternate."; return false;
        }
        team = directory.team;
        if (!algorithms.insert(directory.oid).second) {
            error = "CodeDirectory collection duplicates a hash-agility algorithm."; return false;
        }
        std::string digest, oid;
        if (!Digest(bytes, directory, digest) || !Oid(directory.oid, oid)) { error = "Unable to encode native CodeDirectory hash-agility values."; return false; }
        plist_array_append_item(array, plist_new_data(digest.data(), 20));
        v2.values_der.push_back(Tlv(0x30, oid + Tlv(0x04, digest)));
    }
    if (!ValidateProvisioningSigningCertificate(bundle, credential, error, team)) return false;
    char* xml = nullptr; uint32_t size = 0;
    const auto status = plist_to_xml(hashes.value, &xml, &size);
    std::string plist_bytes;
    if (xml && status == PLIST_ERR_SUCCESS) plist_bytes.assign(xml, size);
    std::free(xml);
    if (plist_bytes.empty()) { error = "Unable to serialize CodeDirectory cdhashes."; return false; }
    const CmsAuthenticatedAttribute v1{"1.2.840.113635.100.9.1", {Tlv(0x04, plist_bytes)}};
    completed = credential.SignDetachedCms(directories.front(), {v1, v2}, cms, error);
    return completed;
}
}
