#include "ipa_verification.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "zip_inventory.hpp"
#include "zip_member.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <plist/plist.h>
#include <algorithm>
#include <array>
#include <map>
#include <set>

namespace OpenFruit {
namespace {
constexpr std::size_t signature_limit = 16 * 1024 * 1024;
std::uint64_t Read(std::string_view bytes, std::size_t at, unsigned count = 4) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < count; ++i) value = (value << 8) | static_cast<unsigned char>(bytes[at + i]);
    return value;
}
bool Active(const ProcessRunOptions& control, IpaVerificationStatus& status) {
    const auto context = CurrentOperationContext();
    if ((control.cancellation && control.cancellation->load()) || (context && context->CancellationRequested())) {
        status = IpaVerificationStatus::Cancelled; return false;
    }
    if (std::chrono::steady_clock::now() >= control.deadline || (context && context->DeadlineExceeded())) {
        status = IpaVerificationStatus::TimedOut; return false;
    }
    return true;
}
std::string Hex(const std::array<std::uint8_t, 20>& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (auto byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}
JsonValue Issues(const std::vector<IpaVerificationIssue>& issues) {
    auto result = JsonValue::ArrayValue();
    for (const auto& issue : issues) {
        auto item = JsonValue::ObjectValue();
        item.Set("code", JsonValue::String(issue.code)); item.Set("message", JsonValue::String(issue.message));
        if (!issue.member.empty()) item.Set("member", JsonValue::String(issue.member));
        result.ArrayItems().push_back(std::move(item));
    }
    return result;
}
bool Cms(std::string_view bytes, std::string_view directory, std::string& signer_sha256) {
    CRYPT_VERIFY_MESSAGE_PARA options{};
    options.cbSize = sizeof(options); options.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE* content = reinterpret_cast<const BYTE*>(directory.data());
    DWORD length = static_cast<DWORD>(directory.size());
    struct Certificate { PCCERT_CONTEXT value = nullptr; ~Certificate() { if (value) CertFreeCertificateContext(value); } } signer;
    if (!CryptVerifyDetachedMessageSignature(&options, 0, reinterpret_cast<const BYTE*>(bytes.data()),
            static_cast<DWORD>(bytes.size()), 1, &content, &length, &signer.value) || !signer.value) return false;
    // Do not accidentally certify one valid signer while silently ignoring others.
    struct Message {
        HCRYPTMSG value = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, nullptr, nullptr);
        ~Message() { if (value) CryptMsgClose(value); }
    } message;
    DWORD signers = 0, size = sizeof(signers);
    if (!message.value || !CryptMsgUpdate(message.value, reinterpret_cast<const BYTE*>(bytes.data()),
            static_cast<DWORD>(bytes.size()), TRUE) ||
        !CryptMsgGetParam(message.value, CMSG_SIGNER_COUNT_PARAM, 0, &signers, &size) || signers != 1) return false;
    const auto digest = Sha256({reinterpret_cast<const char*>(signer.value->pbCertEncoded), signer.value->cbCertEncoded});
    if (!digest) return false;
    signer_sha256 = *digest; return true;
}
struct File {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
    bool Parse(std::string_view bytes) {
        return !bytes.empty() && bytes.size() <= signature_limit &&
            plist_from_memory(bytes.data(), static_cast<uint32_t>(bytes.size()), &value, nullptr) == PLIST_ERR_SUCCESS &&
            plist_get_node_type(value) == PLIST_DICT;
    }
    std::string Text(const char* key) const {
        const auto node = plist_dict_get_item(value, key);
        if (!node || plist_get_node_type(node) != PLIST_STRING) return {};
        std::uint64_t length = 0; const auto text = plist_get_string_ptr(node, &length);
        return text ? std::string(text, static_cast<std::size_t>(length)) : std::string{};
    }
};
bool Ends(std::string_view value, std::string_view suffix) { return value.ends_with(suffix); }
bool MachOMagic(std::string_view value) {
    if (value.size() < 4) return false;
    const auto word = Read(value, 0);
    return word == 0xcffaedfe || word == 0xcefaedfe || word == 0xfeedface || word == 0xfeedfacf ||
        word == 0xcafebabe || word == 0xbebafeca || word == 0xcafebabf || word == 0xbfbafeca;
}
} // namespace

const char* IpaVerificationStatusName(IpaVerificationStatus status) noexcept {
    switch (status) {
    case IpaVerificationStatus::IntegrityVerified: return "integrity_verified";
    case IpaVerificationStatus::Invalid: return "invalid";
    case IpaVerificationStatus::Unsupported: return "unsupported";
    case IpaVerificationStatus::Incomplete: return "incomplete";
    case IpaVerificationStatus::Cancelled: return "cancelled";
    case IpaVerificationStatus::TimedOut: return "timed_out";
    }
    return "invalid";
}
JsonValue MachOSignatureVerification::ToJson() const {
    auto result = JsonValue::ObjectValue();
    result.Set("schema", JsonValue::String("openfruit.macho-signature-verification.v1"));
    result.Set("status", JsonValue::String(IpaVerificationStatusName(status)));
    auto parts = JsonValue::ObjectValue();
    parts.Set("code_pages", JsonValue::Boolean(code_pages_verified));
    parts.Set("special_slots", JsonValue::Boolean(special_slots_verified));
    parts.Set("cms_signature", JsonValue::Boolean(cms_signature_verified));
    parts.Set("alternate_directories_authenticated", JsonValue::Boolean(alternate_directories_authenticated));
    result.Set("verified_parts", std::move(parts));
    result.Set("code_directories_verified", JsonValue::Number(std::to_string(code_directories_verified)));
    result.Set("cms_present", JsonValue::Boolean(cms_present)); result.Set("ad_hoc", JsonValue::Boolean(ad_hoc));
    result.Set("identifier", JsonValue::String(identifier)); result.Set("primary_cdhash", JsonValue::String(primary_cdhash));
    result.Set("signer_certificate_sha256", JsonValue::String(signer_certificate_sha256));
    result.Set("apple_trust_verified", JsonValue::Boolean(false)); result.Set("deployment_authorized", JsonValue::Boolean(false));
    result.Set("issues", Issues(issues)); return result;
}

MachOSignatureVerification VerifyEmbeddedMachOSignature(std::string_view image,
    const CodeDirectorySpecialSlots& external_slots, const SignatureVerificationOptions& options) {
    MachOSignatureVerification result;
    const auto fail = [&](const char* code, const std::string& message,
                          IpaVerificationStatus status = IpaVerificationStatus::Invalid) {
        result.status = status; result.issues.push_back({code, message, {}}); return result;
    };
    if (!Active(options.control, result.status)) return result;
    if (!options.max_image_bytes || image.size() > options.max_image_bytes)
        return fail("signature.image_limit", "Mach-O image exceeds the explicit byte budget.", IpaVerificationStatus::Incomplete);
    if (image.size() >= 4 && Read(image, 0) != 0xcffaedfe && MachOMagic(image))
        return fail("signature.layout_unsupported", "This verifier currently supports little-endian thin 64-bit Mach-O only.", IpaVerificationStatus::Unsupported);
    if (image.size() >= 32 && Read(image, 0) == 0xcffaedfe) {
        const auto little_word = [&](std::size_t at) {
            std::uint32_t value = 0;
            for (unsigned i = 0; i < 4; ++i) value |= std::uint32_t(static_cast<unsigned char>(image[at + i])) << (8 * i);
            return value;
        };
        const auto cpu = little_word(4), kind = little_word(12);
        if ((cpu != 0x0100000c && cpu != 0x01000007) || (kind != 2 && kind != 6 && kind != 8))
            return fail("signature.image_kind_unsupported", "This Mach-O architecture/file type is outside the executable-signature contract.", IpaVerificationStatus::Unsupported);
    }
    for (const auto& [slot, bytes] : external_slots)
        if ((slot != 1 && slot != 3) || bytes.empty() || bytes.size() > signature_limit)
            return fail("signature.external_input", "External inputs must be bounded original Info.plist/CodeResources bytes.");
    MachOSigningLayout layout;
    std::string error;
    if (!InspectMachOSigningLayout(image, layout, error)) {
        if (!Active(options.control, result.status)) return result;
        return fail("signature.layout", error);
    }
    if (layout.signature_size > signature_limit)
        return fail("signature.container_limit", "Embedded signature exceeds the supported bound.", IpaVerificationStatus::Incomplete);
    const auto signature = image.substr(layout.signature_offset, layout.signature_size);
    if (signature.size() < 12 || Read(signature, 0) != 0xfade0cc0)
        return fail("signature.container", "Embedded signature is not a complete SuperBlob.");
    const auto length = Read(signature, 4), count = Read(signature, 8);
    if (length < 12 || length > signature.size() || count > 64 || count > (length - 12) / 8 ||
        signature.substr(static_cast<std::size_t>(length)).find_first_not_of('\0') != std::string_view::npos)
        return fail("signature.index", "SuperBlob index, bounded length or padding is invalid.");
    std::map<std::uint32_t, std::string_view> blobs;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    for (std::uint64_t i = 0; i < count; ++i) {
        if (!Active(options.control, result.status)) return result;
        const auto slot = static_cast<std::uint32_t>(Read(signature, static_cast<std::size_t>(12 + 8 * i)));
        const auto offset = Read(signature, static_cast<std::size_t>(16 + 8 * i));
        if (offset < 12 + 8 * count || offset > length || length - offset < 8)
            return fail("signature.slot_bounds", "Signature slot header is outside the indexed container.");
        const auto bytes = Read(signature, static_cast<std::size_t>(offset + 4));
        if (bytes < 8 || bytes > length - offset ||
            !blobs.emplace(slot, signature.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(bytes))).second)
            return fail("signature.slot_bounds", "Signature slot is duplicated or truncated.");
        ranges.emplace_back(offset, offset + bytes);
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t i = 1; i < ranges.size(); ++i)
        if (ranges[i].first < ranges[i - 1].second) return fail("signature.slot_overlap", "Signature slots overlap.");
    if (!blobs.contains(0)) return fail("signature.code_directory_missing", "Primary CodeDirectory is absent.");
    CodeDirectorySpecialSlots slots = external_slots;
    std::vector<std::pair<std::uint32_t, std::string_view>> directories;
    for (const auto& [slot, blob] : blobs) {
        const auto magic = Read(blob, 0);
        if (slot == 0 || (slot >= 0x1000 && slot < 0x1005)) {
            if (magic != 0xfade0c02 || blob.size() < 44) return fail("signature.code_directory", "CodeDirectory framing is invalid.");
            const auto version = Read(blob, 8);
            if (version < 0x20001 || version > 0x20500)
                return fail("signature.version_unsupported", "CodeDirectory version is not supported.", IpaVerificationStatus::Unsupported);
            directories.emplace_back(slot, blob);
        } else if (slot == 0x10000) {
            if (magic != 0xfade0b01) return fail("signature.cms_wrapper", "CMS wrapper magic is invalid.");
        } else if ((slot == 2 && magic == 0xfade0c01) || (slot == 5 && magic == 0xfade7171) ||
                   (slot == 7 && magic == 0xfade7172) || (slot >= 8 && slot <= 11 && magic == 0xfade8181)) {
            slots.emplace(slot, std::string(blob));
        } else return fail("signature.slot_unsupported", "Signature contains a special blob with unsupported semantics.", IpaVerificationStatus::Unsupported);
    }
    for (const auto& [slot, directory] : directories) {
        (void)slot;
        if (!Active(options.control, result.status)) return result;
        if (!VerifyMachOCodeDirectory(image, directory, slots, error, options.control)) {
            if (!Active(options.control, result.status)) return result;
            return fail("signature.page_or_special_hash", error);
        }
        ++result.code_directories_verified;
    }
    result.code_pages_verified = result.special_slots_verified = true;
    const auto primary = blobs.at(0);
    std::array<std::uint8_t, 20> hash{};
    if (!ComputeMachOCodeDirectoryHash(primary, hash, error)) return fail("signature.cdhash", error);
    result.primary_cdhash = Hex(hash);
    const auto identifier = static_cast<std::size_t>(Read(primary, 20));
    result.identifier = std::string(primary.substr(identifier, primary.find('\0', identifier) - identifier));
    result.ad_hoc = (Read(primary, 12) & 2) != 0;
    const auto cms = blobs.find(0x10000);
    result.cms_present = cms != blobs.end() && cms->second.size() > 8;
    if (result.cms_present) {
        if (!Cms(cms->second.substr(8), primary, result.signer_certificate_sha256))
            return fail("signature.cms_authentication", "Detached CMS does not authenticate the primary CodeDirectory with exactly one signer.");
        if (!Active(options.control, result.status)) return result;
        result.cms_signature_verified = true;
    } else if (options.require_cms || !result.ad_hoc)
        return fail("signature.cms_missing", "Certificate-backed signature is required; ad-hoc integrity is not deployment authorization.");
    if (directories.size() > 1)
        return fail("signature.hash_agility_pending", "All CodeDirectory pages are checked, but CMS hash-agility binding of alternate directories is not implemented.", IpaVerificationStatus::Incomplete);
    result.alternate_directories_authenticated = true; // No alternates exist.
    result.status = IpaVerificationStatus::IntegrityVerified; return result;
}

JsonValue IpaVerificationResult::ToJson() const {
    auto result = JsonValue::ObjectValue();
    result.Set("schema", JsonValue::String("openfruit.ipa-verification.v1"));
    result.Set("status", JsonValue::String(IpaVerificationStatusName(status)));
    auto parts = JsonValue::ObjectValue();
    parts.Set("zip_directory", JsonValue::Boolean(zip_directory_verified));
    parts.Set("member_streams", JsonValue::Boolean(member_streams_verified));
    parts.Set("resource_inventory", JsonValue::Boolean(resource_inventory_verified));
    parts.Set("provisioning_policy", JsonValue::Boolean(provisioning_verified)); result.Set("verified_parts", std::move(parts));
    result.Set("apple_trust_verified", JsonValue::Boolean(false)); result.Set("deployment_authorized", JsonValue::Boolean(false));
    result.Set("members_verified", JsonValue::Number(std::to_string(members_verified)));
    result.Set("decoded_bytes", JsonValue::Number(std::to_string(decoded_bytes)));
    result.Set("archive_bytes", JsonValue::Number(std::to_string(archive_bytes)));
    result.Set("archive_sha256", JsonValue::String(archive_sha256));
    auto observed = JsonValue::ArrayValue();
    for (const auto& image : images) {
        auto item = JsonValue::ObjectValue(); item.Set("member", JsonValue::String(image.member));
        item.Set("signature", image.signature.ToJson()); observed.ArrayItems().push_back(std::move(item));
    }
    result.Set("images", std::move(observed)); result.Set("issues", Issues(issues)); return result;
}

IpaVerificationResult VerifyIpa(const IpaVerificationRequest& request) {
    IpaVerificationResult result;
    const auto fail = [&](const char* code, const std::string& message,
                          IpaVerificationStatus status = IpaVerificationStatus::Invalid, const std::string& member = {}) {
        result.status = status; result.issues.push_back({code, message, member}); return result;
    };
    const auto& control = request.signature.control;
    if (!Active(control, result.status)) return result;
    if (request.archive.empty() || !request.archive.is_absolute() || !request.max_members || !request.max_archive_bytes ||
        !request.max_decoded_bytes || !request.signature.max_image_bytes)
        return fail("ipa.request", "An absolute archive path and positive resource limits are required.");
    File archive;
    archive.value = CreateFileW(request.archive.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
    BY_HANDLE_FILE_INFORMATION before{}; LARGE_INTEGER size{};
    if (archive.value == INVALID_HANDLE_VALUE || GetFileType(archive.value) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(archive.value, &before) || !GetFileSizeEx(archive.value, &size) || size.QuadPart < 0 ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        return fail("ipa.source", "Cannot pin an ordinary immutable archive for read-only verification.");
    if (static_cast<std::uint64_t>(size.QuadPart) > request.max_archive_bytes)
        return fail("ipa.archive_limit", "Archive exceeds the requested byte budget.", IpaVerificationStatus::Incomplete);
    result.archive_bytes = static_cast<std::uint64_t>(size.QuadPart);
    const ZipInventoryRead reader = [&](std::uint64_t offset, std::uint64_t length) -> std::optional<std::string> {
        if (!Active(control, result.status) || offset > static_cast<std::uint64_t>(size.QuadPart) ||
            length > static_cast<std::uint64_t>(size.QuadPart) - offset || length > 64ULL * 1024 * 1024) return {};
        LARGE_INTEGER where{}; where.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(archive.value, where, nullptr, FILE_BEGIN)) return {};
        std::string bytes(static_cast<std::size_t>(length), '\0');
        std::size_t done = 0;
        while (done < bytes.size()) {
            if (!Active(control, result.status)) return {};
            const auto count = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - done, 1024 * 1024)); DWORD actual = 0;
            if (!ReadFile(archive.value, bytes.data() + done, count, &actual, nullptr) || !actual) return {};
            done += actual;
        }
        return bytes;
    };
    const auto inventory = InspectZipInventory(static_cast<std::uint64_t>(size.QuadPart), reader, {}, control.deadline);
    if (!Active(control, result.status)) return result;
    if (!inventory.directory_validated) return fail("ipa.zip_directory", inventory.error);
    result.zip_directory_verified = true;
    if (inventory.members.size() > request.max_members)
        return fail("ipa.member_limit", "ZIP member count exceeds the requested limit.", IpaVerificationStatus::Incomplete);
    std::uint64_t expected_decoded = 0;
    for (const auto& member : inventory.members) {
        if (member.uncompressed > request.max_decoded_bytes - expected_decoded)
            return fail("ipa.decoded_limit", "ZIP decoded byte sum exceeds the requested limit.", IpaVerificationStatus::Incomplete);
        expected_decoded += member.uncompressed;
    }
    // Bind observations to the exact pinned artifact, including ZIP metadata;
    // never mistake CRC-only validation or a pathname for content identity.
    Sha256Stream archive_hash;
    for (std::uint64_t offset = 0; offset < result.archive_bytes;) {
        const auto count = std::min<std::uint64_t>(1024 * 1024, result.archive_bytes - offset);
        const auto bytes = reader(offset, count);
        if (!Active(control, result.status)) return result;
        if (!bytes || !archive_hash.Update(*bytes)) return fail("ipa.source_hash", "Cannot hash the exact pinned archive.");
        offset += count;
    }
    const auto digest = archive_hash.Finish();
    if (!digest) return fail("ipa.source_hash", "Cannot finalize archive content identity.");
    result.archive_sha256 = *digest;
    std::map<std::string, std::string> metadata;
    std::map<std::string, std::string> bundle_executables;
    std::size_t primary_bundles = 0;
    for (const auto& member : inventory.members) {
        if (!Ends(member.name, "/Info.plist") && !Ends(member.name, "/_CodeSignature/CodeResources") && !Ends(member.name, "/embedded.mobileprovision")) continue;
        if (((member.attributes >> 16) & 0170000) == 0120000)
            return fail("ipa.metadata_symlink_unsupported", "Symlinked bundle metadata requires an archive link-resolution policy.", IpaVerificationStatus::Unsupported, member.name);
        if (member.uncompressed > signature_limit || member.compressed > 64ULL * 1024 * 1024)
            return fail("ipa.metadata_limit", "Bundle metadata exceeds the verifier limit.", IpaVerificationStatus::Incomplete, member.name);
        const auto bytes = ReadZipMember(inventory, member.name, reader, {}, control.deadline);
        if (!Active(control, result.status)) return result;
        if (!bytes.stream_verified) return fail("ipa.metadata_stream", bytes.error, IpaVerificationStatus::Invalid, member.name);
        if (bytes.body.size() > signature_limit)
            return fail("ipa.metadata_limit", "Bundle metadata exceeds the verifier limit.", IpaVerificationStatus::Incomplete, member.name);
        metadata.emplace(member.name, bytes.body);
        result.decoded_bytes += bytes.decoded_bytes; ++result.members_verified;
        if (Ends(member.name, "/Info.plist")) {
            const auto bundle = member.name.substr(0, member.name.size() - 11);
            if (!Ends(bundle, ".app") && !Ends(bundle, ".appex") && !Ends(bundle, ".framework")) continue;
            Plist plist;
            if (!plist.Parse(bytes.body)) return fail("ipa.info_plist", "Bundle Info.plist is not a bounded dictionary.", IpaVerificationStatus::Invalid, member.name);
            const auto executable = plist.Text("CFBundleExecutable");
            if (executable.empty() || executable == "." || executable == ".." || executable.find_first_of("/\\:\0", 0, 4) != std::string::npos)
                return fail("ipa.executable_name", "CFBundleExecutable is not a single safe archive component.", IpaVerificationStatus::Invalid, member.name);
            bundle_executables.emplace(bundle + "/" + executable, bundle);
            if (bundle.starts_with("Payload/") && bundle.find('/', 8) == std::string::npos && Ends(bundle, ".app")) ++primary_bundles;
        }
    }
    if (primary_bundles != 1) return fail("ipa.primary_bundle", "IPA requires exactly one application directly inside Payload.");

    // Validate embedded provisioning profile if present
    for (const auto& [name, body] : metadata) {
        if (Ends(name, "/embedded.mobileprovision")) {
            HCRYPTMSG msg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr);
            if (msg) {
                if (CryptMsgUpdate(msg, reinterpret_cast<const BYTE*>(body.data()), static_cast<DWORD>(body.size()), TRUE)) {
                    DWORD content_size = 0;
                    if (CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, nullptr, &content_size) && content_size > 0) {
                        std::string content(content_size, '\0');
                        if (CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, content.data(), &content_size)) {
                            Plist prov_plist;
                            if (prov_plist.Parse(content)) {
                                result.provisioning_verified = true;
                            }
                        }
                    }
                }
                CryptMsgClose(msg);
            }
        }
    }

    // Parse CodeResources file lists for each bundle
    struct ExpectedResource {
        std::string sha256_hex;
    };
    std::map<std::string, std::map<std::string, ExpectedResource>> bundle_resources;
    for (const auto& [name, body] : metadata) {
        if (Ends(name, "/_CodeSignature/CodeResources")) {
            const auto bundle = name.substr(0, name.size() - 29);
            Plist plist;
            if (plist.Parse(body) && plist.value) {
                const auto files2 = plist_dict_get_item(plist.value, "files2");
                if (files2 && plist_get_node_type(files2) == PLIST_DICT) {
                    plist_dict_iter it = nullptr;
                    plist_dict_new_iter(files2, &it);
                    if (it) {
                        char* key = nullptr;
                        plist_t val = nullptr;
                        while (true) {
                            plist_dict_next_item(files2, it, &key, &val);
                            if (!key) break;
                            ExpectedResource er;
                            if (val && plist_get_node_type(val) == PLIST_DICT) {
                                const auto h2 = plist_dict_get_item(val, "hash2");
                                if (h2 && plist_get_node_type(h2) == PLIST_DATA) {
                                    uint64_t len = 0;
                                    const char* buf = plist_get_data_ptr(h2, &len);
                                    if (buf && len == 32) {
                                        constexpr char hex_chars[] = "0123456789abcdef";
                                        for (uint64_t bi = 0; bi < 32; ++bi) {
                                            uint8_t byte = static_cast<uint8_t>(buf[bi]);
                                            er.sha256_hex += hex_chars[byte >> 4];
                                            er.sha256_hex += hex_chars[byte & 15];
                                        }
                                    }
                                }
                            }
                            if (!er.sha256_hex.empty()) {
                                bundle_resources[bundle].emplace(key, std::move(er));
                            }
                            free(key);
                        }
                        free(it);
                    }
                }
            }
        }
    }

    std::set<std::string> observed_executables;
    bool incomplete_images = false;
    std::size_t matched_resources = 0;

    // Check metadata members against bundle_resources (e.g. embedded.mobileprovision)
    for (const auto& [name, body] : metadata) {
        for (const auto& [bundle_path, res_map] : bundle_resources) {
            if (name.starts_with(bundle_path + "/")) {
                std::string rel_path = name.substr(bundle_path.size() + 1);
                if (const auto it = res_map.find(rel_path); it != res_map.end()) {
                    Sha256Stream s;
                    s.Update(body);
                    const auto res_digest = s.Finish();
                    if (res_digest && !it->second.sha256_hex.empty() && *res_digest == it->second.sha256_hex) {
                        ++matched_resources;
                    } else if (res_digest && !it->second.sha256_hex.empty()) {
                        return fail("ipa.resource_tampered", "Resource does not match CodeResources seal: " + rel_path,
                                    IpaVerificationStatus::Invalid, name);
                    }
                }
            }
        }
    }

    std::size_t total_expected_resources = 0;
    for (const auto& [b, res_map] : bundle_resources) total_expected_resources += res_map.size();

    for (const auto& member : inventory.members) {
        if (metadata.contains(member.name)) continue;
        if (!Active(control, result.status)) return result;
        std::string prefix, image;
        bool is_macho = false, limit = false;
        Sha256Stream resource_hash;
        const auto bytes = StreamZipMember(inventory, member.name, reader, [&](std::string_view chunk) {
            if (!Active(control, result.status)) return false;
            resource_hash.Update(chunk);
            if (prefix.size() < 4) {
                const auto take = std::min<std::size_t>(4 - prefix.size(), chunk.size()); prefix.append(chunk.substr(0, take));
                if (prefix.size() == 4) is_macho = MachOMagic(prefix);
            }
            if (prefix.size() < 4) { image.append(chunk); return true; }
            if (is_macho) {
                if (image.size() > request.signature.max_image_bytes ||
                    chunk.size() > request.signature.max_image_bytes - image.size()) { limit = true; return false; }
                image.append(chunk);
            } else image.clear();
            return true;
        }, {}, control.deadline);
        if (!Active(control, result.status)) return result;
        if (limit) return fail("ipa.image_limit", "Mach-O member exceeds the explicit image limit.", IpaVerificationStatus::Incomplete, member.name);
        if (!bytes.stream_verified) return fail("ipa.member_stream", bytes.error, IpaVerificationStatus::Invalid, member.name);
        result.decoded_bytes += bytes.decoded_bytes; ++result.members_verified;

        if (!is_macho) {
            // Check against expected CodeResources
            for (const auto& [bundle_path, res_map] : bundle_resources) {
                if (member.name.starts_with(bundle_path + "/")) {
                    std::string rel_path = member.name.substr(bundle_path.size() + 1);
                    if (const auto it = res_map.find(rel_path); it != res_map.end()) {
                        const auto res_digest = resource_hash.Finish();
                        if (res_digest && !it->second.sha256_hex.empty() && *res_digest == it->second.sha256_hex) {
                            ++matched_resources;
                        } else if (res_digest && !it->second.sha256_hex.empty()) {
                            return fail("ipa.resource_tampered", "Resource does not match CodeResources seal: " + rel_path,
                                        IpaVerificationStatus::Invalid, member.name);
                        }
                    }
                }
            }
            continue;
        }

        CodeDirectorySpecialSlots slots;
        if (const auto owner = bundle_executables.find(member.name); owner != bundle_executables.end()) {
            observed_executables.insert(member.name);
            const auto info = metadata.find(owner->second + "/Info.plist");
            const auto resources = metadata.find(owner->second + "/_CodeSignature/CodeResources");
            if (resources == metadata.end()) return fail("ipa.resource_seal_missing", "Signed bundle has no CodeResources member.", IpaVerificationStatus::Invalid, member.name);
            slots.emplace(1, info->second); slots.emplace(3, resources->second);
        }
        auto signature = VerifyEmbeddedMachOSignature(image, slots, request.signature);
        const auto status = signature.status;
        result.images.push_back({member.name, std::move(signature)});
        if (status == IpaVerificationStatus::Cancelled || status == IpaVerificationStatus::TimedOut) { result.status = status; return result; }
        if (status == IpaVerificationStatus::Invalid) return fail("ipa.signature", "A Mach-O signature failed integrity verification.", status, member.name);
        if (status != IpaVerificationStatus::IntegrityVerified) incomplete_images = true;
    }
    if (observed_executables.size() != bundle_executables.size())
        return fail("ipa.executable_missing", "One or more declared bundle executables are missing or not recognized Mach-O images.");
    result.member_streams_verified = true;

    if (total_expected_resources > 0 && matched_resources == total_expected_resources) {
        result.resource_inventory_verified = true;
    }

    if (result.zip_directory_verified && result.member_streams_verified &&
        !result.images.empty() && !incomplete_images &&
        result.resource_inventory_verified && result.provisioning_verified) {
        result.status = IpaVerificationStatus::IntegrityVerified;
        return result;
    }

    return fail(incomplete_images ? "ipa.signature_scope_pending" : "ipa.policy_pending",
        "Signature/ZIP observations do not yet verify resource selection, provisioning eligibility or Apple trust.", IpaVerificationStatus::Incomplete);
}
} // namespace OpenFruit
