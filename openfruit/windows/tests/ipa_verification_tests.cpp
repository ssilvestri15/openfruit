#include "ipa_verification.hpp"
#include "macho_code_directory.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void Put(std::string& bytes, std::size_t at, std::uint64_t value, unsigned count = 4, bool little = false) {
    for (unsigned i = 0; i < count; ++i) { bytes[at + (little ? i : count - i - 1)] = static_cast<char>(value & 255); value >>= 8; }
}
void Append(std::string& bytes, std::uint64_t value, unsigned count) {
    const auto at = bytes.size(); bytes.resize(at + count); Put(bytes, at, value, count, true);
}
std::uint32_t Crc(std::string_view bytes) {
    std::uint32_t value = ~0u;
    for (const unsigned char byte : bytes) {
        value ^= byte;
        for (unsigned i = 0; i < 8; ++i) value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1)));
    }
    return ~value;
}
struct OwnedDirectory {
    const fs::path parent = fs::absolute(fs::temp_directory_path()).lexically_normal();
    const fs::path path = parent / ("OPENFRUIT-ipa-verifier-" + NewOperationId());
    OwnedDirectory() { fs::create_directory(path); }
    ~OwnedDirectory() {
        if (path.is_absolute() && path.parent_path() == parent && path.filename().wstring().starts_with(L"OPENFRUIT-ipa-verifier-")) {
            std::error_code ignored; fs::remove_all(path, ignored);
        }
    }
};
void Write(const fs::path& file, const std::string& bytes) {
    std::ofstream output(file, std::ios::binary); output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(output), "Unable to write isolated owned fixture");
}
struct OwnedSigner {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    PCCERT_CONTEXT certificate = nullptr;
    ~OwnedSigner() {
        if (certificate) CertFreeCertificateContext(certificate);
        if (key) NCryptFreeObject(key);
        if (provider) NCryptFreeObject(provider);
    }
    OwnedSigner() {
        Require(NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS, "Ephemeral provider failed");
        Require(NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, nullptr, 0, 0) == ERROR_SUCCESS &&
            NCryptFinalizeKey(key, 0) == ERROR_SUCCESS, "Ephemeral RSA key failed");
        DWORD length = 0;
        Require(CertStrToNameW(X509_ASN_ENCODING, L"CN=OPENFRUIT Owned Verifier Test", CERT_X500_NAME_STR,
            nullptr, nullptr, &length, nullptr), "Owned certificate name failed");
        std::vector<BYTE> name(length);
        Require(CertStrToNameW(X509_ASN_ENCODING, L"CN=OPENFRUIT Owned Verifier Test", CERT_X500_NAME_STR,
            nullptr, name.data(), &length, nullptr), "Owned certificate name bytes failed");
        CERT_NAME_BLOB subject{length, name.data()};
        CRYPT_ALGORITHM_IDENTIFIER algorithm{const_cast<char*>(szOID_RSA_SHA256RSA), {0, nullptr}};
        certificate = CertCreateSelfSignCertificate(key, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
            nullptr, &algorithm, nullptr, nullptr, nullptr);
        Require(certificate != nullptr, "Owned self-signed certificate failed");
        CERT_KEY_CONTEXT context{}; context.cbSize = sizeof(context); context.hNCryptKey = key; context.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
        Require(CertSetCertificateContextProperty(certificate, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG,
            &context), "Owned certificate key association failed");
    }
    std::string Detached(std::string_view directory) const {
        CRYPT_SIGN_MESSAGE_PARA options{}; options.cbSize = sizeof(options);
        options.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        options.pSigningCert = certificate; options.HashAlgorithm.pszObjId = const_cast<char*>(szOID_NIST_sha256);
        PCCERT_CONTEXT cert = certificate;
        options.cMsgCert = 1; options.rgpMsgCert = &cert;
        const BYTE* content = reinterpret_cast<const BYTE*>(directory.data());
        DWORD length = static_cast<DWORD>(directory.size()), size = 0;
        Require(CryptSignMessage(&options, TRUE, 1, &content, &length, nullptr, &size), "Owned detached CMS sizing failed");
        std::string cms(size, '\0');
        Require(CryptSignMessage(&options, TRUE, 1, &content, &length, reinterpret_cast<BYTE*>(cms.data()), &size), "Owned detached CMS failed");
        cms.resize(size); return cms;
    }
    std::string Enveloped(std::string_view content) const {
        CRYPT_SIGN_MESSAGE_PARA options{}; options.cbSize = sizeof(options);
        options.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        options.pSigningCert = certificate; options.HashAlgorithm.pszObjId = const_cast<char*>(szOID_NIST_sha256);
        PCCERT_CONTEXT cert = certificate;
        options.cMsgCert = 1; options.rgpMsgCert = &cert;
        const BYTE* data = reinterpret_cast<const BYTE*>(content.data());
        DWORD length = static_cast<DWORD>(content.size()), size = 0;
        Require(CryptSignMessage(&options, FALSE, 1, &data, &length, nullptr, &size), "Owned enveloped CMS sizing failed");
        std::string cms(size, '\0');
        Require(CryptSignMessage(&options, FALSE, 1, &data, &length, reinterpret_cast<BYTE*>(cms.data()), &size), "Owned enveloped CMS failed");
        cms.resize(size); return cms;
    }
};

std::string Image() {
    // Isolated well-formed linker-layout fixture; BuildMachOCodeDirectory computes
    // all page/special hashes itself. No expected digest is supplied to verifier.
    std::string image(12288, '\0');
    Put(image, 0, 0xfeedfacf, 4, true); Put(image, 4, 0x100000c, 4, true);
    Put(image, 12, 2, 4, true); Put(image, 16, 3, 4, true); Put(image, 20, 160, 4, true);
    for (const unsigned at : {32u, 104u}) {
        Put(image, at, 0x19, 4, true); Put(image, at + 4, 72, 4, true);
        Put(image, at + 32, 16384, 8, true); Put(image, at + 56, at == 32 ? 5 : 1, 4, true);
        Put(image, at + 60, at == 32 ? 5 : 1, 4, true);
    }
    image.replace(40, 6, "__TEXT"); Put(image, 56, 0x100000000, 8, true); Put(image, 80, 8192, 8, true);
    image.replace(112, 10, "__LINKEDIT"); Put(image, 128, 0x100004000, 8, true);
    Put(image, 144, 8192, 8, true); Put(image, 152, 4096, 8, true);
    Put(image, 176, 0x1d, 4, true); Put(image, 180, 16, 4, true);
    Put(image, 184, 8192, 4, true); Put(image, 188, 4096, 4, true);
    return image;
}
std::string SignedImage(const CodeDirectorySpecialSlots& external, const OwnedSigner* signer, bool alternate = false) {
    auto image = Image();
    std::string directory, error;
    Require(BuildMachOCodeDirectory(image, "org.openfruit.owned", "OWNEDTEAM1", external, directory, error), error.c_str());
    if (!signer) Put(directory, 12, 2);
    std::map<std::uint32_t, std::string> blobs{{0, directory}};
    if (alternate) blobs.emplace(0x1000, directory);
    if (signer) {
        const auto cms = signer->Detached(directory);
        std::string wrapper(8, '\0'); Put(wrapper, 0, 0xfade0b01); Put(wrapper, 4, 8 + cms.size());
        wrapper += cms; blobs.emplace(0x10000, std::move(wrapper));
    }
    std::string signature(12 + blobs.size() * 8, '\0');
    Put(signature, 0, 0xfade0cc0); Put(signature, 8, blobs.size());
    std::size_t index = 12;
    for (const auto& [slot, blob] : blobs) {
        Put(signature, index, slot); Put(signature, index + 4, signature.size()); signature += blob; index += 8;
    }
    Put(signature, 4, signature.size()); Require(signature.size() <= 4096, "Owned signature exceeds fixed region");
    image.replace(8192, signature.size(), signature); return image;
}
std::string StoredZip(const std::vector<std::pair<std::string, std::string>>& members) {
    std::string bytes, directory;
    for (const auto& [name, body] : members) {
        const auto offset = bytes.size(); const auto crc = Crc(body);
        Append(bytes, 0x04034b50, 4); Append(bytes, 20, 2); Append(bytes, 0x800, 2);
        Append(bytes, 0, 2); Append(bytes, 0, 4); Append(bytes, crc, 4);
        Append(bytes, body.size(), 4); Append(bytes, body.size(), 4); Append(bytes, name.size(), 2); Append(bytes, 0, 2);
        bytes += name; bytes += body;
        Append(directory, 0x02014b50, 4); Append(directory, (3 << 8) | 20, 2); Append(directory, 20, 2);
        Append(directory, 0x800, 2); Append(directory, 0, 2); Append(directory, 0, 4); Append(directory, crc, 4);
        Append(directory, body.size(), 4); Append(directory, body.size(), 4); Append(directory, name.size(), 2);
        Append(directory, 0, 2); Append(directory, 0, 2); Append(directory, 0, 2); Append(directory, 0, 2);
        Append(directory, 0100644u << 16, 4); Append(directory, offset, 4); directory += name;
    }
    const auto at = bytes.size(); bytes += directory;
    Append(bytes, 0x06054b50, 4); Append(bytes, 0, 2); Append(bytes, 0, 2);
    Append(bytes, members.size(), 2); Append(bytes, members.size(), 2);
    Append(bytes, directory.size(), 4); Append(bytes, at, 4); Append(bytes, 0, 2); return bytes;
}

struct CancelHash final : EventSink {
    std::shared_ptr<std::atomic<bool>> flag;
    bool triggered = false;
    void Emit(OperationEvent event) noexcept override {
        if (event.kind == "signing.code-directory.verify-progress" &&
            event.data.Get("pages_verified") && event.data.Get("pages_verified")->Int() == 1) {
            triggered = true; flag->store(true);
        }
    }
};
} // namespace

int main() {
    try {
        const std::string info = "<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>Owned</string>"
            "<key>CFBundleIdentifier</key><string>org.openfruit.owned</string></dict></plist>";
        const std::string resources = "<plist version=\"1.0\"><dict><key>files2</key><dict/></dict></plist>";
        const CodeDirectorySpecialSlots external{{1, info}, {3, resources}};
        OwnedSigner signer;
        const auto image = SignedImage(external, &signer);
        const auto valid = VerifyEmbeddedMachOSignature(image, external);
        Require(valid.status == IpaVerificationStatus::IntegrityVerified && valid.cms_signature_verified &&
            valid.code_pages_verified && valid.special_slots_verified && valid.code_directories_verified == 1,
            "Certificate-backed byte verifier did not authenticate original computed hashes/CMS");
        Require(!valid.ToJson().Get("apple_trust_verified")->Bool() && !valid.ToJson().Get("deployment_authorized")->Bool(),
            "Owned self-signed fixture was promoted to Apple trust/deployment authority");
        auto tampered = image; tampered[2000] ^= 1;
        Require(VerifyEmbeddedMachOSignature(tampered, external).status == IpaVerificationStatus::Invalid, "Tampered code page passed");
        auto altered_slots = external; altered_slots[1] += " ";
        Require(VerifyEmbeddedMachOSignature(image, altered_slots).status == IpaVerificationStatus::Invalid, "Altered original Info.plist passed");
        altered_slots = external; altered_slots[3] += " ";
        Require(VerifyEmbeddedMachOSignature(image, altered_slots).status == IpaVerificationStatus::Invalid, "Altered CodeResources passed");
        Require(VerifyEmbeddedMachOSignature(image).status == IpaVerificationStatus::Invalid, "Missing external seals passed");
        tampered = image; Put(tampered, 8192 + 24, 28);
        Require(VerifyEmbeddedMachOSignature(tampered, external).status == IpaVerificationStatus::Invalid, "Overlapping signature slots passed");
        tampered = image;
        const auto signature_length = [&] { std::uint32_t v = 0; for (unsigned i = 0; i < 4; ++i) v = (v << 8) | static_cast<unsigned char>(image[8196 + i]); return v; }();
        tampered[8192 + signature_length - 1] ^= 1;
        Require(VerifyEmbeddedMachOSignature(tampered, external).status == IpaVerificationStatus::Invalid, "Tampered CMS passed");
        const auto alternate = VerifyEmbeddedMachOSignature(SignedImage(external, &signer, true), external);
        Require(alternate.status == IpaVerificationStatus::Incomplete && alternate.code_directories_verified == 2 &&
            !alternate.alternate_directories_authenticated, "Unchecked alternate hash-agility was silently certified");
        const auto adhoc = SignedImage({}, nullptr);
        Require(VerifyEmbeddedMachOSignature(adhoc).status == IpaVerificationStatus::Invalid, "Default certificate policy accepted ad-hoc signature");
        SignatureVerificationOptions allow_adhoc; allow_adhoc.require_cms = false;
        Require(VerifyEmbeddedMachOSignature(adhoc, {}, allow_adhoc).status == IpaVerificationStatus::IntegrityVerified, "Explicit ad-hoc byte integrity failed");
        auto expired = allow_adhoc; expired.control.deadline = std::chrono::steady_clock::now();
        Require(VerifyEmbeddedMachOSignature(adhoc, {}, expired).status == IpaVerificationStatus::TimedOut, "Expired deadline was ignored");
        auto sink = std::make_shared<CancelHash>(); sink->flag = std::make_shared<std::atomic<bool>>(false);
        auto context = std::make_shared<OperationContext>(); context->sink = sink;
        SignatureVerificationOptions cancel; cancel.control.cancellation = sink->flag;
        {
            OperationBinding binding(context);
            const auto cancelled = VerifyEmbeddedMachOSignature(image, external, cancel);
            Require(sink->triggered && cancelled.status == IpaVerificationStatus::Cancelled && !cancelled.code_pages_verified,
                "Explicit cancellation was not propagated inside the shared CodeDirectory verifier");
        }
        OwnedDirectory scratch;
        const auto archive = scratch.path / "Owned.ipa";
        const std::vector<std::pair<std::string, std::string>> members{
            {"Payload/Owned.app/Info.plist", info}, {"Payload/Owned.app/_CodeSignature/CodeResources", resources},
            {"Payload/Owned.app/Owned", image}, {"Payload/Owned.app/resource.txt", "resource original bytes"}};
        const auto original = StoredZip(members); Write(archive, original);
        const auto stamp = fs::last_write_time(archive);
        IpaVerificationRequest request; request.archive = archive;
        const auto inspected = VerifyIpa(request);
        Require(inspected.status == IpaVerificationStatus::Incomplete && inspected.zip_directory_verified &&
            inspected.member_streams_verified && inspected.members_verified == members.size() && inspected.images.size() == 1 &&
            inspected.images.front().signature.status == IpaVerificationStatus::IntegrityVerified &&
            inspected.archive_sha256 == *Sha256(original) && inspected.archive_bytes == original.size(),
            "ZIP snapshot did not reach the real signature verifier or fabricated complete IPA verification");
        Require(fs::last_write_time(archive) == stamp && fs::file_size(archive) == original.size(), "Read-only verifier mutated archive metadata");
        auto bad_members = members; bad_members[2].second[2000] ^= 1;
        Write(archive, StoredZip(bad_members));
        Require(VerifyIpa(request).status == IpaVerificationStatus::Invalid, "ZIP with recomputed CRC concealed altered Mach-O pages");
        Write(archive, original); request.max_members = 1;
        Require(VerifyIpa(request).status == IpaVerificationStatus::Incomplete, "Member budget was ignored or called corrupt input");
        request.max_members = 20000; request.signature.control.cancellation = std::make_shared<std::atomic<bool>>(true);
        Require(VerifyIpa(request).status == IpaVerificationStatus::Cancelled, "Cancelled archive verification proceeded");

        // Test fully sealed IPA: CodeResources contains valid sha256 + embedded.mobileprovision present
        auto unhex = [](std::string_view hex) {
            std::string out;
            for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
                out.push_back(static_cast<char>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16) & 0xff));
            }
            return out;
        };
        auto base64 = [](std::string_view bytes) {
            DWORD length = 0;
            if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length) || !length) return std::string{};
            std::string result(length, '\0');
            if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &length)) return std::string{};
            while (!result.empty() && result.back() == '\0') result.pop_back();
            return result;
        };

        const auto res_sha256 = *Sha256("resource original bytes");
        const auto res_b64 = base64(unhex(res_sha256));
        const std::string sealed_resources = "<plist version=\"1.0\"><dict><key>files2</key><dict>"
            "<key>resource.txt</key><dict><key>hash2</key><data>" + res_b64 + "</data></dict>"
            "</dict></dict></plist>";
        const std::string profile_xml = "<plist version=\"1.0\"><dict><key>AppIDName</key><string>Owned</string>"
            "<key>ExpirationDate</key><date>2099-01-01T00:00:00Z</date></dict></plist>";
        const auto signed_profile = signer.Enveloped(profile_xml);
        const CodeDirectorySpecialSlots sealed_slots{{1, info}, {3, sealed_resources}};
        const auto sealed_image = SignedImage(sealed_slots, &signer);

        const std::vector<std::pair<std::string, std::string>> fully_sealed_members{
            {"Payload/Owned.app/Info.plist", info},
            {"Payload/Owned.app/_CodeSignature/CodeResources", sealed_resources},
            {"Payload/Owned.app/embedded.mobileprovision", signed_profile},
            {"Payload/Owned.app/Owned", sealed_image},
            {"Payload/Owned.app/resource.txt", "resource original bytes"}
        };
        const auto sealed_archive_path = scratch.path / "FullySealed.ipa";
        Write(sealed_archive_path, StoredZip(fully_sealed_members));
        IpaVerificationRequest sealed_req; sealed_req.archive = sealed_archive_path;
        const auto sealed_result = VerifyIpa(sealed_req);
        Require(sealed_result.status == IpaVerificationStatus::IntegrityVerified,
            "Fully sealed IPA with matching CodeResources and embedded.mobileprovision was not verified as IntegrityVerified");
        Require(sealed_result.resource_inventory_verified, "Resource inventory was not marked verified");
        Require(sealed_result.provisioning_verified, "Provisioning profile was not marked verified");

        // Tamper with sealed resource
        auto tampered_members = fully_sealed_members;
        tampered_members[4].second = "resource tampered bytes!!";
        const auto tampered_archive_path = scratch.path / "TamperedResource.ipa";
        Write(tampered_archive_path, StoredZip(tampered_members));
        IpaVerificationRequest tampered_req; tampered_req.archive = tampered_archive_path;
        const auto tampered_result = VerifyIpa(tampered_req);
        Require(tampered_result.status == IpaVerificationStatus::Invalid, "Tampered resource was not detected as Invalid");

        std::cout << "PASS: independent signature/ZIP byte verification; Apple trust and full IPA policy remain explicit\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
