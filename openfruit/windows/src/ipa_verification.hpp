#pragma once

#include "json_value.hpp"
#include "macho_code_directory.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace OpenFruit {
enum class IpaVerificationStatus { IntegrityVerified, Invalid, Unsupported, Incomplete, Cancelled, TimedOut };

struct IpaVerificationIssue {
    std::string code, message, member;
};

struct SignatureVerificationOptions {
    ProcessRunOptions control;
    bool require_cms = true;
    std::uint64_t max_image_bytes = 512ULL * 1024 * 1024;
};

struct MachOSignatureVerification {
    IpaVerificationStatus status = IpaVerificationStatus::Invalid;
    bool code_pages_verified = false, special_slots_verified = false;
    bool cms_present = false, cms_signature_verified = false;
    bool alternate_directories_authenticated = false, ad_hoc = false;
    std::size_t code_directories_verified = 0;
    std::string identifier, primary_cdhash, signer_certificate_sha256;
    std::vector<IpaVerificationIssue> issues;
    JsonValue ToJson() const;
};

// Verifies original bytes without a signing credential or external signer.
// IntegrityVerified is this byte-level contract only: it never establishes
// Apple trust, provisioning authorization, resource inventory or deployability.
MachOSignatureVerification VerifyEmbeddedMachOSignature(std::string_view image,
    const CodeDirectorySpecialSlots& external_slots = {},
    const SignatureVerificationOptions& options = {});

struct IpaVerificationRequest {
    std::filesystem::path archive;
    SignatureVerificationOptions signature;
    std::uint64_t max_archive_bytes = 8ULL * 1024 * 1024 * 1024;
    std::uint64_t max_decoded_bytes = 4ULL * 1024 * 1024 * 1024;
    std::size_t max_members = 20000;
};

struct IpaMachOObservation {
    std::string member;
    MachOSignatureVerification signature;
};

struct IpaVerificationResult {
    IpaVerificationStatus status = IpaVerificationStatus::Invalid;
    bool zip_directory_verified = false, member_streams_verified = false;
    bool resource_inventory_verified = false, provisioning_verified = false;
    std::size_t members_verified = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t archive_bytes = 0;
    std::string archive_sha256;
    std::vector<IpaMachOObservation> images;
    std::vector<IpaVerificationIssue> issues;
    JsonValue ToJson() const;
};

// Reads one pinned ordinary archive using the existing ZIP inventory/stream
// validators; never extracts or mutates files. A sound signature-only inspection
// returns Incomplete until CodeResources inventory, provisioning and Apple trust
// policies are implemented. It must not authorize deployment as a full IPA pass.
IpaVerificationResult VerifyIpa(const IpaVerificationRequest& request);
const char* IpaVerificationStatusName(IpaVerificationStatus status) noexcept;
} // namespace OpenFruit
